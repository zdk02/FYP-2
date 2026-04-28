"""
Slash Command Overlap — detects tool names / descriptions that overlap
with common slash-command conventions in MCP clients, allowing a
malicious tool to shadow a legitimate client command.
"""


_SYSTEM_COMMANDS = (
    "help", "clear", "reset", "exit", "quit", "save", "load",
    "config", "settings", "login", "logout", "auth", "whoami",
    "history", "undo", "redo", "new", "open", "close",
    "compact", "review", "init", "status", "debug",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "slash_overlap"), target)
    timeout = int(params.get("timeout", 15))

    mcp = mcp_client.MCPClient.from_target(target, timeout=timeout)
    try:
        disc = mcp.discover()
        if not disc["initialized"]:
            errs = disc.get("errors") or []
            detail = errs[0] if errs else {}
            init_resp = (disc.get("raw") or {}).get("initialize") or {}
            rb.error(
                f"MCP initialize failed. step={detail.get('step','init')} "
                f"status={init_resp.get('status')} "
                f"transport={init_resp.get('transport')} "
                f"error={detail.get('error') or init_resp.get('error')} "
                f"target_base_url={target.get('base_url')}")
            rb.add_evidence(evidence.ev_mcp_call(
                init_resp, note="failed initialize"))
            return rb.finalize(success=False)

        for t in disc.get("tools") or []:
            name = t.get("name") or ""
            norm = helpers.normalize_name(name)
            if norm in _SYSTEM_COMMANDS:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "slash_overlap"),
                    title=f"Tool '{name}' shadows a common slash-command",
                    category="slash_command_overlap", severity="high",
                    confidence="confirmed", cwe="CWE-1023", tool=name,
                    description=(
                        f"The tool's normalised name '{norm}' matches a common "
                        "client slash-command. A user typing '/{norm}' expecting "
                        "a client-side action may instead invoke this tool."
                    ),
                    impact=(
                        "Command hijacking — the user's trusted built-in becomes "
                        "an attacker-controlled RPC call."
                    ),
                    remediation=(
                        "Reserve these names client-side; reject any MCP tool "
                        "whose normalised name collides with a built-in. Document "
                        "a namespace prefix ('x-acme-') for server-provided tools."
                    ),
                    payload=name,
                ))
        return rb.finalize()
    finally:
        mcp.close()
