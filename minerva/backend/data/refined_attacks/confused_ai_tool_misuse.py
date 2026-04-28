"""
ConfusedAI Tool Misuse — detects tools whose NAME suggests one function
but whose DESCRIPTION implies another, creating ambiguity that tricks
the LLM into wrong tool selection.
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "confused_ai"), target)
    timeout = int(params.get("timeout", 20))

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

        tools = disc.get("tools") or []
        _NAME_VERBS = {
            "read": ("write", "modify", "delete", "exec"),
            "list": ("delete", "create", "modify"),
            "get":  ("set", "write", "delete"),
            "check": ("create", "delete", "modify"),
            "view": ("edit", "write", "delete"),
        }
        for t in tools:
            name = (t.get("name") or "").lower()
            desc = (t.get("description") or "").lower()
            for verb, conflicts in _NAME_VERBS.items():
                if name.startswith(verb) or f"_{verb}" in name:
                    hit = next((c for c in conflicts if c in desc), None)
                    if hit:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "confused_ai"),
                            title=f"Name/description semantic mismatch on '{t.get('name')}'",
                            category="confused_ai", severity="medium",
                            confidence="high", cwe="CWE-1023",
                            tool=t.get("name"),
                            description=(
                                f"Tool name suggests '{verb}' semantics but description "
                                f"contains '{hit}' — an LLM may misroute dangerous calls."
                            ),
                            remediation=(
                                "Enforce name/behaviour parity via linting on tool "
                                "registration. Reject tools where a read-verb "
                                "describes a write behaviour."
                            ),
                            payload=f"name='{t.get('name')}' desc_verb='{hit}'",
                            evidence=[evidence.ev_raw("tool manifest", t)],
                        ))
                        break
        return rb.finalize()
    finally:
        mcp.close()
