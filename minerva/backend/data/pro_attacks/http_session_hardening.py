"""
HTTP Session Hardening (Pro) — MCP-novel.

When MCP is served over HTTP/SSE and the server uses cookies / a
session ID for state binding, the same web-app weaknesses apply:

  1. Cookies missing HttpOnly / Secure / SameSite — session theft via XSS,
     transit interception, cross-site requests.
  2. Session fixation — server accepts a client-supplied session ID
     before authentication and keeps using it after, allowing an
     attacker to pre-set the victim's session.
  3. Predictable session IDs — issued IDs follow a pattern (sequential,
     low-entropy, time-based) allowing brute-force / next-ID guessing.
  4. Mcp-Session-Id header without binding — MCP 2025-03-26 streamable
     HTTP defines `Mcp-Session-Id` headers; check that the server
     refuses to accept tampered values.

Confidence: confirmed if cookie attributes literally missing or
fixation accepted; high for low-entropy IDs.
"""

import math as _math
import re as _re
import time as _time
import statistics as _stats


def _http_get(url: str, headers: dict | None = None, timeout: float = 10.0):
    return requests.get(url, headers=headers or {}, timeout=timeout,
                        allow_redirects=False)


def _http_post(url: str, json_body: dict, headers: dict | None = None,
               timeout: float = 10.0):
    return requests.post(url, json=json_body, headers=headers or {},
                         timeout=timeout, allow_redirects=False)


def _entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    chars = {}
    for c in s:
        chars[c] = chars.get(c, 0) + 1
    total = sum(chars.values())
    h = 0.0
    for c, n in chars.items():
        p = n / total
        h -= p * _math.log2(p)
    return h * len(s)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "http_session_hardening"),
        target=target,
    )
    timeout = float(params.get("timeout", 10))
    test_cookie_flags = bool(params.get("test_cookie_flags", True))
    test_fixation = bool(params.get("test_fixation", True))
    test_predictability = bool(params.get("test_predictability", True))
    test_mcp_session = bool(params.get("test_mcp_session_header", True))
    sample_count = int(params.get("sample_count", 10))

    base_url = target.get("base_url") or ""
    if not base_url:
        proto = target.get("protocol") or "http"
        base_url = f"{proto}://{target.get('host')}:{target.get('port')}"
    rb.info(f"HTTP session hardening probe: {base_url}")
    use_tls = base_url.startswith("https://")

    # --- Vector 1: cookie flags ------------------------------------------
    cookies_collected = []
    set_cookie_headers = []
    try:
        r = _http_get(base_url, timeout=timeout)
        # Could be OPTIONS-blocked; try a JSON-RPC initialize POST instead
        if r.status_code >= 400:
            r = _http_post(base_url, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18",
                           "capabilities": {}, "clientInfo":
                           {"name": "minerva-probe", "version": "1.0"}},
            }, headers={"Accept": "application/json, text/event-stream"},
                          timeout=timeout)
        rb.add_evidence(evidence.ev_http(
            {"method": r.request.method, "url": base_url},
            {"status": r.status_code, "headers": dict(r.headers),
             "body": (r.text or "")[:500]},
            note="initial GET/POST",
        ))
        # Collect Set-Cookie headers (raw — multiple values allowed)
        sc = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else []
        if not sc:
            sc_one = r.headers.get("Set-Cookie")
            if sc_one:
                sc = [sc_one]
        set_cookie_headers = sc
        for cookie_header in sc:
            cookies_collected.append(cookie_header)
            cname = cookie_header.split("=", 1)[0]
            lower = cookie_header.lower()
            httponly = "httponly" in lower
            secure = "secure" in lower
            samesite_match = _re.search(r"samesite\s*=\s*(strict|lax|none)", lower)
            samesite = samesite_match.group(1) if samesite_match else None

            if test_cookie_flags:
                missing = []
                if not httponly:
                    missing.append("HttpOnly")
                if use_tls and not secure:
                    missing.append("Secure")
                if not samesite:
                    missing.append("SameSite")
                elif samesite == "none" and not secure:
                    missing.append("SameSite=None requires Secure")
                if missing:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "http_session_hardening"),
                        title=f"Cookie {cname!r} missing protective flags: {', '.join(missing)}",
                        category="http_cookie_flags",
                        severity="medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                        confidence="confirmed",
                        parameter="Set-Cookie",
                        payload=cookie_header[:200],
                        description=(
                            f"Cookie {cname!r} is set without "
                            f"{', '.join(missing)}."
                        ),
                        impact=(
                            "Session-bearing cookies without HttpOnly are "
                            "stealable via XSS; without Secure they leak over "
                            "HTTP; without SameSite they are sent on "
                            "cross-site requests (CSRF surface)."
                        ),
                        remediation=(
                            "Set HttpOnly; Secure; SameSite=Lax (or Strict) on "
                            "all session cookies. Use SameSite=None only with "
                            "Secure for cross-site embeds you really want."
                        ),
                        cwe="CWE-1004",
                    ))
    except Exception as e:
        rb.warn(f"initial probe failed: {e}")

    # --- Vector 2: session fixation --------------------------------------
    if test_fixation and base_url:
        forced_id = "MINERVAFIXATIONPROBE12345"
        try:
            r = _http_get(base_url, headers={"Cookie": f"session={forced_id}"},
                          timeout=timeout)
            sc = (r.headers.get("Set-Cookie") or "")
            # If the server doesn't issue a NEW session in response to
            # request carrying our forced ID, it's a fixation candidate.
            if forced_id in sc or (not sc and r.status_code < 400):
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "http_session_hardening"),
                    title="Server appears to accept attacker-supplied session IDs (fixation candidate)",
                    category="http_session_fixation",
                    severity="medium", confidence="medium",
                    parameter="Cookie",
                    payload=forced_id,
                    description=(
                        "Sending a request with a client-supplied session "
                        "cookie did not provoke the server to issue a fresh "
                        "session ID. If the server later authenticates this "
                        "session without rotation, an attacker who pre-sets "
                        "the victim's session can hijack it post-login."
                    ),
                    impact="Session hijacking via fixation.",
                    remediation=(
                        "Always rotate the session identifier on privilege "
                        "change (login). Never accept a session ID before "
                        "authentication."
                    ),
                    cwe="CWE-384",
                ))
        except Exception as e:
            rb.warn(f"fixation probe failed: {e}")

    # --- Vector 3: predictability -----------------------------------------
    if test_predictability and base_url:
        ids = []
        try:
            for _ in range(sample_count):
                r = _http_get(base_url, timeout=timeout)
                sc = r.headers.get("Set-Cookie") or ""
                m = _re.search(r"(?:session|sid|sessid|jsessionid|connect\.sid)\s*=\s*([^;]+)",
                               sc, _re.I)
                if not m:
                    # Also check Mcp-Session-Id header if present
                    msid = r.headers.get("mcp-session-id") or r.headers.get("Mcp-Session-Id")
                    if msid:
                        ids.append(msid)
                else:
                    ids.append(m.group(1))
                _time.sleep(0.05)
        except Exception as e:
            rb.warn(f"sampling failed: {e}")

        if len(ids) >= 5:
            entropies = [_entropy_bits(s) for s in ids]
            avg = _stats.mean(entropies)
            rb.info(f"sampled {len(ids)} session IDs; avg shannon entropy {avg:.1f} bits")
            if avg < 80:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "http_session_hardening"),
                    title=f"Low-entropy session identifiers ({avg:.0f} bits avg)",
                    category="http_session_entropy",
                    severity="high" if avg < 60 else "medium",
                    confidence="high",
                    description=(
                        f"Across {len(ids)} sampled sessions, average Shannon "
                        f"entropy is {avg:.1f} bits — well below the 128-bit "
                        f"floor recommended for session IDs. Brute-force or "
                        f"prediction is feasible."
                    ),
                    impact="Session prediction → unauth access.",
                    remediation=(
                        "Generate session IDs from a CSPRNG with at least "
                        "128 bits of entropy (e.g. secrets.token_urlsafe(32))."
                    ),
                    cwe="CWE-330",
                    references=["https://cwe.mitre.org/data/definitions/330.html"],
                ))

    # --- Vector 4: Mcp-Session-Id tampering ------------------------------
    if test_mcp_session and base_url:
        try:
            tampered = "minerva-tampered-session-id"
            r = _http_post(base_url, {
                "jsonrpc": "2.0", "id": 99, "method": "tools/list",
                "params": {},
            }, headers={
                "Mcp-Session-Id": tampered,
                "Accept": "application/json, text/event-stream",
            }, timeout=timeout)
            rb.add_evidence(evidence.ev_http(
                {"method": "POST", "url": base_url,
                 "headers": {"Mcp-Session-Id": tampered}},
                {"status": r.status_code, "body": (r.text or "")[:500]},
                note="tampered Mcp-Session-Id",
            ))
            if r.status_code < 400 and "error" not in (r.text or "").lower():
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "http_session_hardening"),
                    title="Server accepts arbitrary Mcp-Session-Id without binding to issued session",
                    category="http_mcp_session_id",
                    severity="medium", confidence="high",
                    parameter="Mcp-Session-Id",
                    payload=tampered,
                    description=(
                        "The MCP streamable-HTTP transport defines "
                        "Mcp-Session-Id as a server-issued, opaque, "
                        "client-replayable token bound to a session. The "
                        "server processed a tampered value as if it were a "
                        "valid session — likely it isn't tracking the binding "
                        "at all."
                    ),
                    impact=(
                        "If session-bound state holds privileges, an attacker "
                        "can switch context simply by changing this header."
                    ),
                    remediation=(
                        "Maintain a server-side mapping from issued "
                        "Mcp-Session-Id to session state; reject 404 / 400 "
                        "when the header doesn't match a live session."
                    ),
                    cwe="CWE-302",
                ))
        except Exception as e:
            rb.warn(f"mcp-session probe failed: {e}")

    return rb.finalize()
