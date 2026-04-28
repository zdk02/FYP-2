"""
Tool Coverage Hijacking — flags overly-broad tools whose description
could plausibly serve many user intents, letting them intercept tool
routing that should go to more specific siblings.
"""


_BROAD_KEYWORDS = (
    "any", "anything", "general-purpose", "universal", "all",
    "everything", "master", "multi-purpose", "do it all",
    "versatile", "flexible", "various",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "tool_hijack"), target)
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

        tools = disc.get("tools") or []
        for t in tools:
            desc = (t.get("description") or "").lower()
            hit = helpers.contains_any(desc, _BROAD_KEYWORDS)
            # Also penalise extremely short / vague descriptions
            vague = len(desc.strip()) < 30
            if hit or vague:
                word_count = len(desc.split())
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "tool_hijack"),
                    title=f"Overly-broad tool description on '{t.get('name')}'",
                    category="tool_coverage_hijacking",
                    severity="medium",
                    confidence="high" if hit else "medium",
                    cwe="CWE-1023", tool=t.get("name"),
                    description=(
                        f"Description is {word_count} words and contains "
                        f"broad-scope marker '{hit}'." if hit else
                        f"Description is only {word_count} words. An LLM "
                        "selecting tools by description may default to this "
                        "catch-all tool over more specific siblings, letting a "
                        "malicious catch-all intercept sensitive operations."
                    ),
                    impact=(
                        "Routing hijack — specific actions get sent to an "
                        "over-broad tool that can log, modify, or forward them."
                    ),
                    remediation=(
                        "Require descriptions of 10+ words with an explicit "
                        "scope statement. Lint tool manifests for broad-scope "
                        "vocabulary."
                    ),
                    payload=(desc[:200] or "(empty)"),
                ))
        return rb.finalize()
    finally:
        mcp.close()
