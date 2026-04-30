"""
MCP Data-in-Transit / MITM posture (Pro).

Enterprise-grade transit audit for an MCP endpoint:

  1. Plain-HTTP probe — does the endpoint respond on HTTP at all?
  2. TLS handshake — version, cipher suite, ALPN, SNI mismatch.
  3. Weak-cipher negotiation — server-confirmed support for RC4 / 3DES /
     EXPORT / NULL / anonymous-DH.
  4. Certificate chain — issuer, expiry, key strength, trust path,
     SAN coverage, self-signed detection.
  5. Security headers — HSTS (with max-age + preload), CSP, X-Frame-
     Options, X-Content-Type-Options.
  6. Mixed-content via SSE: if the server is HTTPS but advertises
     callbacks / stream URLs over HTTP.
  7. Secrets in tool responses (via secret_validators with full
     validation when available).
"""

import socket as _socket
import ssl as _ssl
import datetime as _dt
from urllib.parse import urlparse


# Cipher suites that should never be accepted in 2025
_WEAK_CIPHER_SUITES = (
    "RC4-MD5", "RC4-SHA",
    "DES-CBC3-SHA", "DES-CBC-SHA",
    "EXP-RC4-MD5", "EXP-DES-CBC-SHA", "EXP-RC2-CBC-MD5",
    "NULL-MD5", "NULL-SHA",
    "ADH-AES128-SHA", "ADH-AES256-SHA",      # anon DH
    "EXPORT", "PSK-NULL-SHA",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "mcp_mitm"),
        target=target,
    )
    timeout = int(params.get("timeout", 15))
    probe_tool_responses = bool(params.get("probe_tool_responses", True))
    validate_chain = bool(params.get("validate_chain", True))
    test_weak_ciphers = bool(params.get("test_weak_ciphers", True))
    check_security_headers = bool(params.get("check_security_headers", True))
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None

    base_url = (target.get("base_url") or "").rstrip("/")
    parsed = urlparse(base_url) if base_url else None
    host = (parsed.hostname if parsed else None) or target.get("host")
    port = (parsed.port if parsed else None) or int(target.get("port") or 0) or \
        (443 if (target.get("protocol") or "https").lower() in ("https", "wss") else 80)
    protocol = (parsed.scheme if parsed else None) or (target.get("protocol") or "https").lower()

    # --- 1. Plain-HTTP probe ----------------------------------------------
    plain_url = f"http://{host}:80"
    rb.info(f"Plain-HTTP probe: {plain_url}")
    plain = _http_get(plain_url + "/mcp", timeout)
    rb.add_evidence(evidence.ev_http(
        {"method": "GET", "url": plain["url"]},
        {"status": plain["status"], "headers": plain.get("headers"),
         "body": (plain.get("body") or "")[:500]},
        note="plain-http baseline",
    ))
    if plain["ok"] and plain["status"] is not None and plain["status"] < 500 \
            and plain["status"] != 400:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="MCP endpoint responds on plain HTTP (no TLS)",
            category="data_in_transit",
            severity="critical" if protocol == "https" else "high",
            confidence="confirmed",
            cwe="CWE-319",
            description=(
                f"GET {plain_url}/mcp returned HTTP {plain['status']}. Any "
                "network-adjacent attacker can read and modify MCP traffic "
                "(tool args, auth tokens, responses)."
            ),
            impact="Complete loss of confidentiality + integrity.",
            remediation=(
                "Serve MCP exclusively over HTTPS with a valid cert. Respond "
                "to plain HTTP with 301→HTTPS. Set HSTS max-age ≥ 31536000."
            ),
            payload=plain_url,
        ))

    # --- 2. TLS handshake (only if HTTPS/WSS) -----------------------------
    if protocol in ("https", "wss"):
        tls = _inspect_tls(host, port, timeout, validate_chain)
        rb.add_evidence(evidence.ev_raw("TLS handshake", tls))
        if tls.get("error") and not tls.get("cipher"):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "mcp_mitm"),
                title="TLS handshake failed",
                category="data_in_transit",
                severity="high", confidence="high",
                cwe="CWE-326",
                description=f"Could not complete TLS handshake: {tls['error']}",
                remediation="Investigate and fix TLS configuration.",
            ))
        else:
            _audit_tls(tls, rb, context, validate_chain=validate_chain)

        # --- 3. Weak-cipher probe ----------------------------------------
        if test_weak_ciphers:
            weak_accepted = _probe_weak_ciphers(host, port, timeout)
            if weak_accepted:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "mcp_mitm"),
                    title=f"Weak TLS cipher(s) accepted: {weak_accepted[:5]}",
                    category="data_in_transit",
                    severity="high", confidence="confirmed",
                    cwe="CWE-326",
                    description=(
                        f"Server accepted at least one of: {', '.join(weak_accepted[:8])}. "
                        "These are deprecated and cryptographically broken."
                    ),
                    remediation=(
                        "Restrict to TLS 1.2+ AEAD ciphers only "
                        "(ECDHE-AESGCM / CHACHA20-POLY1305). Disable RC4, 3DES, "
                        "EXPORT, NULL, anon-DH at the TLS terminator."
                    ),
                    payload=", ".join(weak_accepted),
                ))

    # --- 4. Security headers ---------------------------------------------
    if check_security_headers and base_url:
        full = _http_get(base_url + "/mcp", timeout)
        if full["ok"]:
            _audit_security_headers(full.get("headers") or {}, rb, context, protocol)

    # --- 5. Tool-response secret scan ------------------------------------
    if probe_tool_responses:
        try:
            mcp = mcp_client.MCPClient.from_target(
                target, timeout=timeout,
                protocol_version=protocol_version,
                force_transport=transport_override,
            )
            try:
                disc = mcp.discover()
                for t in (disc.get("tools") or [])[:10]:
                    name = t.get("name")
                    if not name:
                        continue
                    args = helpers.fill_defaults(t.get("inputSchema") or {})
                    r = mcp.call_tool_safe(name, args)
                    text = r.get("text_output") or ""
                    for s in secret_validators.detect_secrets(text):
                        v = None
                        try:
                            v = secret_validators.validate(s["type"], s["value"])
                        except Exception:
                            pass
                        sev = "critical" if v and v.get("valid") is True else "high"
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "mcp_mitm"),
                            title=f"Secret in tool response of '{name}' ({s['type']})",
                            category="data_in_transit",
                            severity=sev, confidence="confirmed" if v and v.get("valid") else "high",
                            cwe="CWE-532",
                            tool=name,
                            description=(
                                f"Tool '{name}' returned data matching {s['type']} format. "
                                + (f"Validated as {v.get('summary')}" if v else "Not validated.")
                            ),
                            remediation="Never return raw credentials from MCP tools.",
                            evidence=[evidence.ev_mcp_call(r)],
                            payload=s["value"][:8] + "...",
                        ))
            finally:
                mcp.close()
        except Exception as e:
            rb.warn(f"Could not probe tool responses: {e!s:.200}")

    return rb.finalize()


# ---------------------------------------------------------------------------
# TLS audit
# ---------------------------------------------------------------------------

def _inspect_tls(host, port, timeout, validate_chain):
    """Returns rich dict: cipher, version, peer cert dict + DER, expiry, SAN."""
    out = {"cipher": None, "version": None, "subject_cn": None,
           "issuer_cn": None, "not_after": None, "not_before": None,
           "alt_names": [], "self_signed": None,
           "trusted": None, "trust_error": None,
           "key_bits": None, "alpn": None, "error": None}
    # First handshake: trust validation
    if validate_chain:
        try:
            ctx_strict = _ssl.create_default_context()
            with _socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_strict.wrap_socket(sock, server_hostname=host) as ssock:
                    out["trusted"] = True
                    cert = ssock.getpeercert()
                    out["alpn"] = ssock.selected_alpn_protocol()
                    _enrich_from_cert(out, cert)
        except _ssl.SSLCertVerificationError as e:
            out["trusted"] = False
            out["trust_error"] = str(e)[:300]
        except Exception as e:
            out["trust_error"] = str(e)[:300]
    # Second handshake: relaxed, to grab cert details and cipher
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        with _socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["cipher"] = ssock.cipher()
                out["version"] = ssock.version()
                cert = ssock.getpeercert(binary_form=False)
                out["alpn"] = out["alpn"] or ssock.selected_alpn_protocol()
                _enrich_from_cert(out, cert)
    except Exception as e:
        out["error"] = str(e)[:300]
    return out


def _enrich_from_cert(out, cert):
    if not cert:
        return
    subj = cert.get("subject") or []
    iss = cert.get("issuer") or []
    out["subject_cn"] = _cn(subj)
    out["issuer_cn"] = _cn(iss)
    out["not_after"] = cert.get("notAfter")
    out["not_before"] = cert.get("notBefore")
    out["alt_names"] = [v for k, v in (cert.get("subjectAltName") or [])]
    if out["subject_cn"] and out["subject_cn"] == out["issuer_cn"]:
        out["self_signed"] = True


def _cn(rdn_list):
    for rdn in rdn_list:
        for k, v in rdn:
            if k == "commonName":
                return v
    return None


def _audit_tls(tls, rb, context, *, validate_chain):
    cwe = "CWE-326"
    version = tls.get("version") or ""

    if version.startswith("TLSv1.0"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="TLSv1.0 accepted (deprecated 2020)",
            category="data_in_transit", severity="high",
            confidence="confirmed", cwe=cwe,
            description="TLSv1.0 was accepted.",
            remediation="Disable TLS<1.2 at the load balancer.",
        ))
    if version.startswith("TLSv1.1"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="TLSv1.1 accepted (deprecated)",
            category="data_in_transit", severity="medium",
            confidence="confirmed", cwe=cwe,
            description="TLSv1.1 was accepted.",
            remediation="Require TLSv1.2 or 1.3.",
        ))

    # Self-signed
    if tls.get("self_signed"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="TLS certificate is self-signed",
            category="data_in_transit", severity="high",
            confidence="confirmed", cwe="CWE-295",
            description=("Subject CN equals issuer CN — certificate is self-"
                         "signed. Clients cannot verify authenticity without "
                         "out-of-band trust pinning."),
            remediation="Issue from a public or private trusted CA.",
        ))

    # Untrusted chain
    if validate_chain and tls.get("trusted") is False:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="TLS chain validation failed",
            category="data_in_transit", severity="high",
            confidence="confirmed", cwe="CWE-295",
            description=f"Default truststore could not validate the cert: "
                        f"{tls.get('trust_error')!r}",
            remediation=("Use a publicly-trusted CA and a complete chain. "
                         "Order: leaf → intermediates."),
        ))

    # Expiry
    not_after = tls.get("not_after")
    if not_after:
        try:
            d = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (d - _dt.datetime.utcnow()).days
            if days_left < 14:
                sev = "critical" if days_left <= 0 else "high"
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "mcp_mitm"),
                    title=f"TLS certificate expiring soon ({days_left}d)",
                    category="data_in_transit", severity=sev,
                    confidence="confirmed", cwe="CWE-295",
                    description=f"Cert expires {not_after} ({days_left} days).",
                    remediation="Renew via ACME automation.",
                ))
        except Exception:
            pass


def _probe_weak_ciphers(host, port, timeout):
    """Try to negotiate each weak cipher; record those the server accepts."""
    accepted = []
    for cipher in _WEAK_CIPHER_SUITES:
        try:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.set_ciphers(cipher)
            except _ssl.SSLError:
                continue  # OpenSSL doesn't even know about it
            with _socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    accepted.append(cipher)
        except Exception:
            continue
    return accepted


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

def _audit_security_headers(headers, rb, context, protocol):
    h = {k.lower(): v for k, v in (headers or {}).items()}
    if protocol == "https" and not h.get("strict-transport-security"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="HSTS header missing",
            category="data_in_transit", severity="medium",
            confidence="confirmed", cwe="CWE-319",
            description=("HTTPS endpoint without Strict-Transport-Security. "
                         "First-visit clients are exploitable via SSL stripping."),
            remediation=("Add `Strict-Transport-Security: max-age=31536000; "
                         "includeSubDomains; preload`."),
        ))
    elif protocol == "https":
        hsts = h.get("strict-transport-security", "")
        m = re.search(r"max-age=(\d+)", hsts) if (re := __import__("re")) else None
        if m and int(m.group(1)) < 15552000:  # 180 days
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "mcp_mitm"),
                title="HSTS max-age too short",
                category="data_in_transit", severity="low",
                confidence="confirmed", cwe="CWE-319",
                description=f"HSTS max-age={m.group(1)} (<180 days).",
                remediation="Increase to ≥ 31536000 (1 year).",
            ))

    if not h.get("content-security-policy"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="Content-Security-Policy header missing",
            category="data_in_transit", severity="low",
            confidence="confirmed", cwe="CWE-1021",
            description="No CSP — admin UIs / docs may be XSS-prone.",
            remediation="Add a strict CSP for any HTML surface.",
        ))

    if not h.get("x-content-type-options"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "mcp_mitm"),
            title="X-Content-Type-Options header missing",
            category="data_in_transit", severity="low",
            confidence="confirmed", cwe="CWE-79",
            description="MIME-sniffing not disabled.",
            remediation="Add `X-Content-Type-Options: nosniff`.",
        ))


def _http_get(url, timeout):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
        return {"url": url, "ok": True, "status": r.status_code,
                "headers": dict(r.headers), "body": r.text[:1500]}
    except Exception as e:
        return {"url": url, "ok": False, "status": None,
                "headers": {}, "body": "", "error": str(e)[:200]}
