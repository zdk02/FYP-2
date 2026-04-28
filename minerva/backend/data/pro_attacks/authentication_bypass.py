"""
Authentication / Authorization Bypass on MCP endpoints.

Pentester questions:
  - Does the server accept MCP calls with NO auth?
  - Does it accept any token (e.g. `Bearer invalid`)?
  - Does it leak different error text for valid-but-wrong-token vs no token
    (token-oracle)?
  - Is tool access uniform — or do some sensitive tools slip past auth?

Requires that the Target has ``auth_config`` set with the legitimate
credentials. The attack compares the authenticated behaviour to the
unauthenticated / malformed-auth behaviour.
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "authentication_bypass"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    test_tool_call = bool(params.get("test_tool_call", True))

    legit_auth = target.get("auth_config") or {}
    if not legit_auth or legit_auth.get("type") in ("", "none"):
        rb.warn("Target has no auth_config — running as a bare reachability test.")

    # 1. Baseline: with the legitimate credentials
    rb.info("Baseline: authenticated initialize")
    client_ok = mcp_client.MCPClient.from_target(target, timeout=timeout)
    try:
        ok_init = client_ok.initialize()
        ok_tl = client_ok.tools_list() if ok_init.get("ok") else None
        rb.add_evidence(evidence.ev_mcp_call(ok_init,
                                              note="authenticated initialize"))
        if ok_tl:
            rb.add_evidence(evidence.ev_mcp_call(ok_tl,
                                                  note="authenticated tools/list"))
    finally:
        client_ok.close()

    auth_success = bool(ok_init.get("ok"))

    # 2. No-auth probe
    noauth_target = dict(target); noauth_target["auth_config"] = {"type": "none"}
    rb.info("Probe: no credentials")
    client_no = mcp_client.MCPClient.from_target(noauth_target, timeout=timeout)
    try:
        no_init = client_no.initialize()
        no_tl = client_no.tools_list() if no_init.get("ok") else None
        rb.add_evidence(evidence.ev_mcp_call(no_init,
                                              note="no-auth initialize"))
    finally:
        client_no.close()
    no_auth_ok = bool(no_init.get("ok"))

    if no_auth_ok and (not legit_auth or legit_auth.get("type") not in ("", "none")):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "authentication_bypass"),
            title="MCP server allows initialize without credentials",
            category="authentication_bypass",
            severity="critical",
            confidence="confirmed",
            cwe="CWE-306",
            description=(
                "Server returned a successful MCP initialize handshake to a "
                "client that supplied no credentials. Either authentication "
                "is not enforced at this endpoint or a bypass exists."
            ),
            impact="Any network-reachable attacker can enumerate and call "
                   "tools, read resources, and potentially trigger any "
                   "other server-side vulnerability.",
            remediation=(
                "Require authentication at the MCP endpoint (gateway or "
                "application level). Reject requests missing Authorization "
                "headers before any JSON-RPC parsing."
            ),
            references=["https://cwe.mitre.org/data/definitions/306.html"],
            evidence=[evidence.ev_mcp_call(no_init)],
        ))

    # 3. Bad-auth probe (should fail the same way no-auth fails)
    bad_target = dict(target); bad_target["auth_config"] = {
        "type": "bearer", "token": "invalid-token-" + "A" * 32}
    client_bad = mcp_client.MCPClient.from_target(bad_target, timeout=timeout)
    try:
        bad_init = client_bad.initialize()
        rb.add_evidence(evidence.ev_mcp_call(bad_init,
                                              note="invalid-token initialize"))
    finally:
        client_bad.close()
    bad_auth_ok = bool(bad_init.get("ok"))

    if bad_auth_ok:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "authentication_bypass"),
            title="MCP server accepts arbitrary bearer tokens",
            category="authentication_bypass",
            severity="critical",
            confidence="confirmed",
            cwe="CWE-287",
            description=(
                "Server accepted a request carrying a syntactically-valid but "
                "random bearer token. Token validation is missing or "
                "insufficient (e.g. signature check disabled)."
            ),
            impact="Equivalent to no authentication.",
            remediation="Verify JWT signatures, check 'iss'/'aud' claims, "
                        "reject expired and unknown tokens.",
            references=["https://cwe.mitre.org/data/definitions/287.html"],
        ))

    # 4. Token-oracle leak
    if not bad_auth_ok and not no_auth_ok:
        if bad_init.get("status") != no_init.get("status") or \
                _text(bad_init) != _text(no_init):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "authentication_bypass"),
                title="Authentication oracle — error messages differ",
                category="authentication_bypass",
                severity="low",
                confidence="high",
                cwe="CWE-204",
                description=(
                    "Responses to 'no token' vs 'invalid token' requests differ "
                    "in status/text. This lets an attacker programmatically "
                    "distinguish valid-but-wrong-scope tokens from total junk, "
                    "aiding credential-stuffing."
                ),
                remediation=(
                    "Return identical generic 401 Unauthorized responses "
                    "regardless of the failure reason."
                ),
                references=["https://cwe.mitre.org/data/definitions/204.html"],
                evidence=[evidence.ev_mcp_call(no_init,
                                                note="no-token response"),
                          evidence.ev_mcp_call(bad_init,
                                                note="bad-token response")],
            ))

    # 5. Per-tool access (requires auth_success). If any tool callable
    # without auth, that's partial bypass.
    if auth_success and ok_tl and test_tool_call:
        tools = (ok_tl.get("result") or {}).get("tools") or []
        client_no2 = mcp_client.MCPClient.from_target(noauth_target,
                                                      timeout=timeout)
        try:
            client_no2.initialize()  # may fail — try tools/call anyway
            for tool in tools[:10]:
                name = tool.get("name")
                if not name:
                    continue
                args = _fill_defaults(tool.get("inputSchema") or {})
                r = client_no2.call_tool_safe(name, args)
                if r.get("ok") and not r.get("is_error"):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "authentication_bypass"),
                        title=f"Tool '{name}' callable without authentication",
                        category="authentication_bypass",
                        severity="high",
                        confidence="confirmed",
                        cwe="CWE-862",
                        tool=name,
                        description=(
                            f"Authenticated request and unauthenticated request "
                            "to this tool both succeeded. Authorization is "
                            "enforced at the transport layer but not per-tool."
                        ),
                        impact="Sensitive tools leak past the auth boundary.",
                        remediation="Enforce authorization per tool, not just "
                                    "per transport.",
                        evidence=[evidence.ev_mcp_call(r)],
                    ))
        finally:
            client_no2.close()

    return rb.finalize()


def _text(resp):
    body = (resp or {}).get("response") or {}
    if isinstance(body, dict):
        return str(body.get("error") or body.get("message") or body)
    return str(body)


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "a", "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out
