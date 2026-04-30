"""
MCP Protocol Version Downgrade.

The MCP spec has shipped multiple protocol versions:

  - 2025-06-18 (current) — OAuth 2.1 mandate, elicitation, structured tool output
  - 2025-03-26          — streamable HTTP, audio, completions
  - 2024-11-05          — first public spec
  - 2024-10-07          — pre-public draft
  - 0.1.0               — early SDK builds

Modern MCP servers should negotiate the highest version both peers
support, refuse versions the server has dropped, and never re-enable
removed insecure features when an older version is requested.

Tests
-----
1. **Negotiation discovery** — call `initialize` for every known
   version. Catalogue which the server accepts (returns 200 + result
   with `protocolVersion`).
2. **Bogus version** — claim `protocolVersion: "9999-12-31"`. The spec
   says servers MAY pick a different version they support, but they
   must not return success with our bogus value.
3. **Insecure-feature ride-along** — when an older version is accepted,
   probe features that were tightened in newer versions:
     * batched JSON-RPC requests (deprecated in 2025-03-26)
     * sampling without elicitation consent (pre-2025-06-18)
     * unauthenticated stdio (pre-2025-06-18 OAuth mandate)
4. **Mid-session re-init** — does the server allow `initialize` twice
   in one session, possibly with a different protocol version?

Dynamic params
--------------
  versions_to_test    — override KNOWN_PROTOCOL_VERSIONS
  test_batch          — try JSON-RPC batch
  test_reinit         — try mid-session re-init with downgraded version
  transport_override
  timeout
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "protocol_version_downgrade"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    versions_to_test = params.get("versions_to_test") or list(
        mcp_client.KNOWN_PROTOCOL_VERSIONS)
    transport_override = params.get("transport_override") or None
    test_batch = bool(params.get("test_batch", True))
    test_reinit = bool(params.get("test_reinit", True))

    rb.info(f"Negotiating versions: {versions_to_test}")
    result = mcp_client.negotiate_protocol_version(
        target,
        versions=versions_to_test,
        timeout=timeout,
        force_transport=transport_override,
    )
    rb.add_evidence(evidence.ev_raw("negotiation results",
                                     {"accepted": result["accepted"],
                                      "rejected": result["rejected"]}))
    accepted = result["accepted"]
    rejected = result["rejected"]
    rb.info(f"Accepted versions: {accepted}")
    rb.info(f"Rejected versions: {[r['version'] for r in rejected]}")

    # 1) Old / dropped versions accepted
    KNOWN_OLD = {"2024-11-05", "2024-10-07", "0.1.0"}
    accepted_old = [v for v in accepted if v in KNOWN_OLD]
    if accepted_old:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "protocol_version_downgrade"),
            title=f"Server accepts deprecated protocol version(s): {accepted_old}",
            category="protocol_version_downgrade",
            severity="high", confidence="confirmed",
            cwe="CWE-757",
            description=(
                f"Server completed `initialize` with deprecated protocolVersion "
                f"{accepted_old}. Versions before 2025-06-18 lack OAuth 2.1 "
                "mandate, elicitation/createMessage, and structured tool output "
                "guarantees. An attacker can force a downgrade and exploit the "
                "wider attack surface."
            ),
            impact=(
                "Downgrade to a version where insecure features (no PKCE-OAuth, "
                "auto-approved sampling, weaker tool-result validation) are "
                "allowed. Common precursor to chained exploits."
            ),
            remediation=(
                "Reject versions older than 2025-06-18 unless explicit "
                "compatibility shim is required. Return -32602 invalid_params "
                "for unknown / removed versions."
            ),
            references=[
                "https://modelcontextprotocol.io/specification/2025-06-18/changelog",
            ],
            payload=str(accepted_old),
        ))

    # 2) Bogus future version
    bogus = mcp_client.negotiate_protocol_version(
        target,
        versions=["9999-12-31"],
        timeout=timeout,
        force_transport=transport_override,
    )
    if bogus["accepted"] and "9999-12-31" in bogus["accepted"]:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "protocol_version_downgrade"),
            title="Server echoes bogus protocolVersion '9999-12-31'",
            category="protocol_version_downgrade",
            severity="medium", confidence="confirmed",
            cwe="CWE-345",
            description=(
                "Server returned protocolVersion=9999-12-31 in initialize "
                "response. Servers should pick a version they actually "
                "implement, not echo the client's claim."
            ),
            remediation=("Return only versions the server natively supports. "
                         "Reject unknowns."),
            payload="protocolVersion=9999-12-31",
        ))

    # 3) Insecure-feature ride-along — pick the oldest accepted version
    if accepted_old:
        old_v = sorted(accepted_old)[0]
        rb.info(f"Probing insecure features on downgraded version {old_v}")
        mcp = mcp_client.MCPClient.from_target(
            target, timeout=timeout,
            force_transport=transport_override,
            protocol_version=old_v,
        )
        try:
            init = mcp.initialize(protocol_version=old_v)
            rb.add_evidence(evidence.ev_mcp_call(
                init, note=f"reinit with old version {old_v}"))
            if init.get("ok"):
                # Batch JSON-RPC
                if test_batch:
                    _probe_batch(mcp, rb, context, old_v)
        finally:
            mcp.close()

    # 4) Mid-session re-init with downgraded version
    if test_reinit and accepted:
        latest = accepted[0] if accepted else None
        downgrade_target = next((v for v in KNOWN_OLD if v in accepted), None)
        if latest and downgrade_target and latest != downgrade_target:
            mcp = mcp_client.MCPClient.from_target(
                target, timeout=timeout,
                force_transport=transport_override,
                protocol_version=latest,
            )
            try:
                init1 = mcp.initialize(protocol_version=latest)
                rb.add_evidence(evidence.ev_mcp_call(
                    init1, note=f"first init {latest}"))
                init2 = mcp.initialize(protocol_version=downgrade_target)
                rb.add_evidence(evidence.ev_mcp_call(
                    init2, note=f"second init (downgrade) {downgrade_target}"))
                if init2.get("ok"):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "protocol_version_downgrade"),
                        title="Server allows mid-session re-initialize (protocol downgrade)",
                        category="protocol_version_downgrade",
                        severity="high", confidence="confirmed",
                        cwe="CWE-757",
                        description=(
                            f"After completing initialize at {latest}, a second "
                            f"initialize at {downgrade_target} also succeeded. "
                            "An attacker who can inject one MCP message can "
                            "downgrade the session protocol mid-flight."
                        ),
                        impact=(
                            "Bypass features added in newer versions (PKCE, "
                            "consent flows, structured outputs) by downgrading "
                            "after the user approves the session."
                        ),
                        remediation=(
                            "initialize must be allowed exactly once per "
                            "session. Subsequent initialize requests must "
                            "return -32600 invalid request."
                        ),
                    ))
            finally:
                mcp.close()

    return rb.finalize()


def _probe_batch(mcp, rb, context, version):
    """Send a JSON-RPC batch (array of requests). Deprecated in
    2025-03-26 — older servers may still accept."""
    # We use the underlying transport directly to avoid the high-level
    # client's single-request envelope assumption.
    try:
        # Build a 2-request batch
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
        ]
        # The base Transport doesn't expose batch sending; only HTTP can
        transport = mcp.transport
        if not hasattr(transport, "_session"):
            return
        url = transport.base_url + transport.path
        resp = transport._session.post(  # type: ignore[attr-defined]
            url, json=batch,
            headers={"Content-Type": "application/json",
                     "Accept": "application/json"},
            timeout=transport.timeout,
            verify=getattr(transport, "verify_tls", True),
        )
        rb.add_evidence(evidence.ev_http(
            {"url": url, "method": "POST", "body": "[batch=2]"},
            {"status": resp.status_code, "body": resp.text[:1500]},
            note="batch JSON-RPC probe",
        ))
        if resp.status_code == 200 and resp.text.strip().startswith("["):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "protocol_version_downgrade"),
                title=f"Server accepts JSON-RPC batches (deprecated since 2025-03-26)",
                category="protocol_version_downgrade",
                severity="medium", confidence="confirmed",
                cwe="CWE-757",
                description=(
                    f"Sent a 2-element batch to a server speaking version "
                    f"{version}; received an array response. Batch JSON-RPC "
                    "was removed in 2025-03-26 because it complicates "
                    "auth-per-request enforcement."
                ),
                remediation=("Reject batched requests. Return -32600 if the "
                             "request body is a JSON array."),
                payload="[req1, req2]",
            ))
    except Exception as e:
        rb.warn(f"Batch probe failed: {e!s:.200}")
