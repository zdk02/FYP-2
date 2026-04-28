"""
MCP Man In The Middle — ACTIVE variant using Minerva's mitm_proxy.

Spins up a proxy in front of the target, records a short window of
normal-looking MCP traffic, then analyses the captured flows for signs
of insecure practices that an on-path attacker would exploit.
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "mitm_active"), target)
    timeout = int(params.get("timeout", 20))
    capture_seconds = int(params.get("capture_seconds", 10))

    base = target.get("base_url") or \
        f"{target.get('protocol','http')}://{target.get('host','localhost')}:{target.get('port',80)}"
    upstream = base.rstrip("/") + "/mcp"
    proxy = mitm_proxy.spawn(upstream_url=upstream, attack_id="mitm_active",
                              ttl=capture_seconds + 10, bind_host="127.0.0.1")
    rb.info(f"Proxy up at {proxy.endpoint} -> {upstream}")
    try:
        # Drive a handshake + tools/list through the proxy so we have
        # concrete flows to audit.
        victim = mcp_client.MCPClient.from_target(
            {"base_url": proxy.endpoint, "path": "/"}, timeout=timeout)
        try:
            victim.discover()
        finally:
            victim.close()

        flows = mitm_proxy.flows(proxy.token)
        rb.info(f"Captured {len(flows)} flow(s)")
        rb.add_evidence(evidence.ev_raw("captured flows (truncated)",
                                         flows[:3]))

        # Analyses ---------------------------------------------------------
        auth_leaks = any("authorization" in
                         {k.lower() for k in (f["request"].get("headers") or {})}
                         for f in flows)
        if auth_leaks:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "mitm_active"),
                title="Auth token observable in MCP request headers",
                category="data_in_transit", severity="critical"
                if (target.get("protocol", "").lower() == "http") else "medium",
                confidence="confirmed", cwe="CWE-319",
                description=(
                    "The captured MCP traffic contained an Authorization "
                    "header. On any non-TLS hop (or TLS with MITM via bad "
                    "cert trust), the token is readable."
                ),
                remediation=(
                    "Always use TLS with cert-pinning in production MCP "
                    "clients. Prefer short-lived tokens + per-request "
                    "signatures when feasible."
                ),
                evidence=[evidence.ev_raw("first captured request headers",
                                          (flows[0]["request"].get("headers")
                                           if flows else {}))],
            ))

        # Response-body secret leak through the proxy
        from app.services.evidence import _safe as _s  # noqa: F401
        for f in flows:
            body = (f["response"].get("body") or "")
            if any(k in body.lower() for k in
                   ("private_key", "apikey", "api_key", "secret")):
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "mitm_active"),
                    title="Credential-like content in MCP response body",
                    category="data_in_transit", severity="high",
                    confidence="high", cwe="CWE-319",
                    description=(
                        "An on-path attacker would have observed credential-"
                        "shaped content in this response body."
                    ),
                    remediation=(
                        "Never return raw credentials from MCP tools; use "
                        "opaque handles resolved server-side."
                    ),
                ))
                break

        return rb.finalize()
    finally:
        mitm_proxy.release(proxy.token)
