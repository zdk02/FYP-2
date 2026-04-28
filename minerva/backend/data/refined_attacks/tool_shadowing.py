"""
Tool Shadowing — description collision detection. Two tools with
similar but non-identical descriptions (semantic near-duplicates) that
an LLM may confuse during routing.
"""

import difflib as _difflib


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "tool_shadow"), target)
    timeout = int(params.get("timeout", 15))
    similarity_threshold = float(params.get("similarity_threshold", 0.85))

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

        tools = [t for t in disc.get("tools") or [] if t.get("description")]
        flagged = set()
        for i, a in enumerate(tools):
            for b in tools[i + 1:]:
                pair = tuple(sorted([a.get("name"), b.get("name")]))
                if pair in flagged: continue
                ratio = _difflib.SequenceMatcher(
                    None, a["description"], b["description"]).ratio()
                if ratio >= similarity_threshold:
                    flagged.add(pair)
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "tool_shadow"),
                        title=f"Near-duplicate descriptions: {pair[0]} vs {pair[1]}",
                        category="tool_shadowing",
                        severity="medium", confidence="high",
                        cwe="CWE-1023",
                        description=(
                            f"Description similarity {ratio:.0%} between "
                            f"'{pair[0]}' and '{pair[1]}'. LLM routing may "
                            "select the wrong tool."
                        ),
                        remediation=(
                            "Make each tool description semantically distinct; "
                            "add a uniqueness check at registration."
                        ),
                        payload=f"similarity={ratio:.2f}",
                    ))
        return rb.finalize()
    finally:
        mcp.close()
