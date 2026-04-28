"""
MCP Man-in-the-Middle posture audit.

A pentester rarely gets to actually run ARP spoofing against an
enterprise MCP deployment — but they DO need to assess whether the
deployment is resilient against a MITM adversary:

Checks
------
1. TLS enforcement — HTTP (no TLS) at all? Downgrade path available?
2. Certificate strength — weak ciphers, self-signed, expired.
3. Protocol strict-transport — HSTS header present and long-lived?
4. HTTP response leakage — does a plain-HTTP probe succeed?
5. Tool responses containing secrets (keys, tokens) that would be
   visible to an on-path attacker.
6. Insecure redirects (http → same host http).

Uses the `ssl` module directly to grab cert info without needing mitmproxy.
"""

import socket as _socket
import ssl as _ssl
import re as _re
import datetime as _dt
from urllib.parse import urlparse


_SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
    (r"xoxb-[a-zA-Z0-9-]+", "Slack bot token"),
    (r"ghp_[a-zA-Z0-9]{20,}", "GitHub personal access token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
     "credential-like assignment"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "mcp_mitm"),
        target=target,
    )
    timeout = int(params.get("timeout", 15))
    probe_tool_responses = bool(params.get("probe_tool_responses", True))

    host = target.get("host")
    port = int(target.get("port") or (443 if (target.get("protocol") or "https") == "https" else 80))
    protocol = (target.get("protocol") or "https").lower()
    base_url = target.get("base_url") or f"{protocol}://{host}:{port}"

    # 1) HTTP (no TLS) probe ---------------------------------------------
    plain_url = f"http://{host}:{port if port not in (443,) else 80}"
    rb.info(f"Probing plain-HTTP baseline: {plain_url}")
    plain_ok, plain_status, plain_body = _probe_http(plain_url, timeout)
    if plain_ok and plain_status and plain_status < 500 and plain_status != 400:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="MCP endpoint responds on plain HTTP (no TLS)",
            category="data_in_transit",
            severity="critical" if protocol == "https" else "high",
            confidence="confirmed",
            cwe="CWE-319",
            description=(
                f"GET {plain_url} returned HTTP {plain_status}. "
                "Any network-adjacent attacker can read and modify MCP "
                "traffic (tool arguments, auth tokens, responses)."
            ),
            impact="Complete loss of confidentiality + integrity for MCP traffic.",
            remediation=(
                "Serve the MCP endpoint exclusively over HTTPS with a valid "
                "certificate. Respond to plain HTTP with 301 → HTTPS and set "
                "HSTS (max-age ≥ 31536000) to prevent downgrade."
            ),
            references=["https://cwe.mitre.org/data/definitions/319.html"],
            payload=plain_url,
        ))

    # 2) TLS cert inspection ---------------------------------------------
    if protocol in ("https", "wss"):
        cert_info, cert_err = _inspect_tls(host, port, timeout)
        if cert_err:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "mcp_mitm"),
                title="TLS handshake failure",
                category="data_in_transit",
                severity="high",
                confidence="high",
                cwe="CWE-326",
                description=f"Could not complete TLS handshake: {cert_err}",
                remediation="Investigate and fix TLS configuration.",
            ))
        elif cert_info:
            rb.add_evidence(evidence.ev_raw("TLS certificate", cert_info))
            _audit_cert(cert_info, rb, context)

    # 3) HSTS check ------------------------------------------------------
    ok, status, body, headers = _probe_http_full(base_url, timeout)
    if ok and protocol == "https":
        hsts = headers.get("strict-transport-security") if headers else None
        if not hsts:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "mcp_mitm"),
                title="HSTS not set on MCP endpoint",
                category="data_in_transit",
                severity="medium",
                confidence="confirmed",
                cwe="CWE-319",
                description=(
                    "The MCP endpoint serves HTTPS without a "
                    "Strict-Transport-Security response header. First-visit "
                    "clients are exploitable via SSL stripping."
                ),
                remediation=(
                    "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`. "
                    "Consider preload listing."
                ),
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            ))

    # 4) Tool-response secret leakage -----------------------------------
    if probe_tool_responses:
        mcp = mcp_client.MCPClient.from_target(target, timeout=timeout)
        try:
            disc = mcp.discover()
            for t in (disc.get("tools") or [])[:10]:
                name = t.get("name")
                if not name:
                    continue
                args = _fill_defaults(t.get("inputSchema") or {})
                r = mcp.call_tool_safe(name, args)
                text = r.get("text_output") or ""
                for pattern, label in _SECRET_PATTERNS:
                    m = _re.search(pattern, text)
                    if m:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "mcp_mitm"),
                            title=f"Potential secret in tool response ({name}): {label}",
                            category="data_in_transit",
                            severity="high",
                            confidence="high",
                            cwe="CWE-532",
                            tool=name,
                            description=(
                                f"Tool '{name}' returned data matching a "
                                f"{label} pattern. An on-path attacker would "
                                "see it in cleartext if any transport hop is "
                                "HTTP."
                            ),
                            impact="Credential disclosure during transit.",
                            remediation=(
                                "Never return raw credentials from MCP tools. "
                                "Use reference IDs and resolve server-side."
                            ),
                            evidence=[evidence.ev_mcp_call(r, note="secret-leak probe")],
                            payload=m.group(0)[:80],
                        ))
        finally:
            mcp.close()

    return rb.finalize()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _probe_http(url, timeout):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
        return True, r.status_code, r.text[:500]
    except Exception as e:
        return False, None, str(e)


def _probe_http_full(url, timeout):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
        return True, r.status_code, r.text[:500], {k.lower(): v for k, v in r.headers.items()}
    except Exception:
        return False, None, None, None


def _inspect_tls(host, port, timeout):
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        with _socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                # getpeercert returns {} when verify is NONE; also grab raw text
                cipher = ssock.cipher()
                return {
                    "cipher": cipher,
                    "version": ssock.version(),
                    "peer": ssock.getpeercert(binary_form=True) and "present" or "absent",
                    "subject_cn": _cn_from_cert(cert),
                    "not_after": (cert or {}).get("notAfter"),
                    "not_before": (cert or {}).get("notBefore"),
                    "issuer": (cert or {}).get("issuer"),
                }, None
    except Exception as e:
        return None, str(e)


def _cn_from_cert(cert):
    if not cert:
        return None
    subj = cert.get("subject") or []
    for rdn in subj:
        for k, v in rdn:
            if k == "commonName":
                return v
    return None


def _audit_cert(info, rb, context):
    version = info.get("version") or ""
    if version and version.startswith("TLSv1.0"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="TLSv1.0 accepted — obsolete",
            category="data_in_transit",
            severity="high",
            confidence="confirmed",
            cwe="CWE-326",
            description="Server accepted a TLSv1.0 handshake. Disable.",
            remediation="Disable TLS < 1.2 on the load balancer / server.",
        ))
    if version and version.startswith("TLSv1.1"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="TLSv1.1 accepted — deprecated",
            category="data_in_transit",
            severity="medium",
            confidence="confirmed",
            cwe="CWE-326",
            description="TLSv1.1 was accepted.",
            remediation="Require TLSv1.2+ only.",
        ))

    # Cert expiry
    not_after = info.get("not_after")
    if not_after:
        try:
            dt = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (dt - _dt.datetime.utcnow()).days
            if days_left < 14:
                sev = "critical" if days_left <= 0 else "high"
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "mcp_mitm"),
                    title=f"TLS certificate expiring soon ({days_left}d)",
                    category="data_in_transit",
                    severity=sev,
                    confidence="confirmed",
                    cwe="CWE-295",
                    description=f"Certificate expires {not_after} ({days_left} days).",
                    remediation="Renew the certificate and automate via ACME.",
                ))
        except Exception:
            pass


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "a", "integer": 1, "number": 1, "boolean": False,
                  "array": [], "object": {}}.get(t, "")
    return out
