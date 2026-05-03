"""
WebSocket Transport Hardening (Pro) — MCP-novel.

When MCP is served over WebSocket (RFC 6455), the transport itself
introduces classes of attack that don't exist on HTTP/SSE/stdio:

  1. ORIGIN HEADER TRUST — server accepts WS upgrades from any Origin.
     Browsers attaching the user's MCP cookies to a malicious page will
     produce Cross-Site WebSocket Hijacking (CSWSH).
  2. SUBPROTOCOL NEGOTIATION — server accepts arbitrary
     `Sec-WebSocket-Protocol` values; downgrade or fingerprint risk.
  3. UNSOLICITED CONTROL FRAMES — server tolerates ping flooding /
     unsolicited pong / close-handshake abuse, opening DoS / state-confusion.
  4. LARGE FRAME / FRAGMENTATION — server allocates without an upper
     bound on payload length; one large frame can OOM the handler.
  5. UPGRADE WITHOUT HTTP AUTH — when bearer/api-key is supposed to
     be presented in an `Authorization` header on the upgrade, server
     skips it and accepts the WS handshake.

This attack issues raw HTTP upgrades (not via MCPClient) so we can
inspect the response status / headers directly.
"""

import socket as _socket
import ssl as _ssl
import base64 as _b64
import hashlib as _hashlib
import os as _os


def _ws_handshake(host: str, port: int, *, path: str = "/",
                  use_tls: bool = False, headers: list[tuple[str, str]] | None = None,
                  timeout: float = 8.0) -> dict:
    """Issue a raw WS upgrade and return the response status + headers."""
    sec_key = _b64.b64encode(_os.urandom(16)).decode()
    base_headers = [
        ("Host", f"{host}:{port}"),
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Key", sec_key),
        ("Sec-WebSocket-Version", "13"),
    ]
    if headers:
        base_headers.extend(headers)
    req = f"GET {path} HTTP/1.1\r\n" + \
          "\r\n".join(f"{k}: {v}" for k, v in base_headers) + "\r\n\r\n"
    sock = _socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req.encode("utf-8"))
        chunks = []
        sock.settimeout(timeout)
        # read until we see end of headers or a small ceiling
        while b"\r\n\r\n" not in b"".join(chunks) and sum(len(c) for c in chunks) < 65536:
            try:
                data = sock.recv(4096)
            except Exception:
                break
            if not data:
                break
            chunks.append(data)
        raw = b"".join(chunks)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    head = raw.decode("latin-1", errors="replace").split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    status_code = 0
    try:
        status_code = int(status_line.split()[1])
    except Exception:
        pass
    resp_headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()
    return {
        "request": {"method": "GET", "url": ("wss" if use_tls else "ws") + f"://{host}:{port}{path}",
                    "headers": dict(base_headers)},
        "response": {"status": status_code, "raw_head": head,
                     "headers": resp_headers},
        "status": status_code,
        "transport": "wss" if use_tls else "ws",
    }


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "ws_transport_hardening"),
        target=target,
    )
    timeout = float(params.get("timeout", 8))
    test_origin_csws = bool(params.get("test_origin_cswsh", True))
    test_subprotocols = bool(params.get("test_subprotocols", True))
    test_no_auth = bool(params.get("test_no_auth", True))

    host = target.get("host") or "localhost"
    port = int(target.get("port") or (443 if (target.get("protocol") in ("wss", "https")) else 80))
    use_tls = (target.get("protocol") in ("wss", "https"))
    path = "/"  # most MCP WS servers serve at root; can be parameterised

    # Discover an MCP path if base_url is set
    base_url = target.get("base_url") or ""
    if base_url and "://" in base_url:
        try:
            from urllib.parse import urlparse
            u = urlparse(base_url)
            path = u.path or "/"
        except Exception:
            pass

    rb.info(f"WS handshake target: {('wss' if use_tls else 'ws')}://{host}:{port}{path}")

    # --- Vector 1: malicious Origin (CSWSH) -------------------------------
    if test_origin_csws:
        for origin in ("http://attacker.example",
                       "https://evil.example",
                       "null"):
            try:
                r = _ws_handshake(host, port, path=path, use_tls=use_tls,
                                  headers=[("Origin", origin)],
                                  timeout=timeout)
                rb.add_evidence(evidence.ev_http(r["request"], r["response"],
                                                 note=f"Origin={origin}"))
                if 100 <= r["status"] <= 101:
                    f = evidence.Finding(
                        attack_id=context.get("attack_id", "ws_transport_hardening"),
                        title=f"Cross-Site WebSocket Hijacking — server accepts Origin: {origin}",
                        category="ws_origin_cswsh",
                        severity="high", confidence="confirmed",
                        parameter="Origin",
                        payload=origin,
                        description=(
                            f"WebSocket upgrade accepted with Origin: {origin}. "
                            "Browser-issued cross-origin WS connections will "
                            "succeed and carry the user's authentication cookies, "
                            "letting a malicious page interact with the MCP "
                            "server as the authenticated user (CSWSH)."
                        ),
                        impact=(
                            "Drive-by takeover of MCP sessions when the user "
                            "visits an attacker-controlled page in the same "
                            "browser they're authenticated to MCP from."
                        ),
                        remediation=(
                            "Validate Origin against an allowlist on every WS "
                            "upgrade. Reject if Origin is missing, 'null', or "
                            "not in the allowlist. Optionally require a CSRF "
                            "token in the upgrade query string."
                        ),
                        cwe="CWE-346",
                        references=[
                            "https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking_(CSWSH)",
                        ],
                    )
                    rb.add_finding(f)
            except Exception as e:
                rb.warn(f"  origin {origin}: {e}")

    # --- Vector 2: arbitrary subprotocols ---------------------------------
    if test_subprotocols:
        for sp in ("minerva-bogus", "json-rpc-2.0", "mcp.v0",
                   "echo, evil, anything"):
            try:
                r = _ws_handshake(host, port, path=path, use_tls=use_tls,
                                  headers=[("Sec-WebSocket-Protocol", sp)],
                                  timeout=timeout)
                accepted = r["status"] == 101
                hdr = r["response"]["headers"].get("sec-websocket-protocol")
                if accepted and hdr and hdr in sp:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "ws_transport_hardening"),
                        title=f"WebSocket subprotocol negotiated without validation: {hdr!r}",
                        category="ws_subprotocol_validation",
                        severity="low", confidence="high",
                        parameter="Sec-WebSocket-Protocol",
                        payload=sp,
                        description=(
                            f"Server echoed back subprotocol {hdr!r} from a "
                            "client-supplied Sec-WebSocket-Protocol header that "
                            "is not part of any defined MCP transport."
                        ),
                        impact=(
                            "Subprotocol fingerprinting; potential downgrade to "
                            "an unintended message format if the server keys "
                            "behaviour off this header."
                        ),
                        remediation=(
                            "Reject upgrades that propose subprotocols outside "
                            "the documented set."
                        ),
                        cwe="CWE-20",
                    ))
            except Exception as e:
                rb.warn(f"  subprotocol {sp!r}: {e}")

    # --- Vector 3: handshake without auth ---------------------------------
    if test_no_auth and (target.get("auth_config") or {}).get("type"):
        try:
            r = _ws_handshake(host, port, path=path, use_tls=use_tls,
                              timeout=timeout)
            if r["status"] == 101:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "ws_transport_hardening"),
                    title="WebSocket upgrade accepted with no Authorization header",
                    category="ws_unauth_upgrade",
                    severity="high", confidence="confirmed",
                    description=(
                        "A target known to require authentication (auth_config "
                        "is configured for this Target) accepted a WS upgrade "
                        "without any Authorization header. Auth is enforced on "
                        "the message layer at best, leaving the upgrade itself "
                        "anonymous."
                    ),
                    impact=(
                        "Pre-auth resource consumption, fingerprinting, and "
                        "potentially message-layer auth bypass if not strictly "
                        "enforced."
                    ),
                    remediation=(
                        "Validate Authorization on the HTTP upgrade itself; "
                        "reject the upgrade with 401 if auth is missing."
                    ),
                    cwe="CWE-306",
                ))
            rb.add_evidence(evidence.ev_http(r["request"], r["response"],
                                             note="no-auth upgrade"))
        except Exception as e:
            rb.warn(f"  no-auth handshake: {e}")

    return rb.finalize()
