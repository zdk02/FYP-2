"""
Tool Poisoning — laser-focused on zero-width / invisible Unicode
injection in every metadata field. (The Pro version covers all
poisoning techniques; this one specialises.)
"""


_ZW = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u2028": "LINE SEPARATOR",
    "\u2029": "PARAGRAPH SEPARATOR",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
}


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "tool_poison"), target)
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

        def _scan(owner, field, text):
            if not text: return
            seen = {c: label for c, label in _ZW.items() if c in text}
            if not seen: return
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "tool_poison"),
                title=f"Invisible Unicode in {owner}/{field}",
                category="tool_poisoning", severity="high",
                confidence="confirmed", cwe="CWE-1007",
                tool=owner, parameter=field,
                description=(
                    f"Field '{field}' of '{owner}' contains invisible "
                    f"Unicode characters: {', '.join(seen.values())}. "
                    "These bypass human review but are ingested verbatim "
                    "by LLMs."
                ),
                impact=(
                    "Hidden instructions smuggled past code review survive "
                    "into every future LLM-tool interaction."
                ),
                remediation=(
                    "Normalize all MCP metadata to printable ASCII + common "
                    "Latin Unicode at ingest. Reject or quarantine entries "
                    "containing control / format characters."
                ),
                payload=text[:400],
            ))

        for t in disc.get("tools") or []:
            name = t.get("name")
            _scan(name, "name", t.get("name", ""))
            _scan(name, "description", t.get("description", ""))
            for pn, pspec in ((t.get("inputSchema") or {}).get("properties") or {}).items():
                _scan(name, f"param:{pn}.description", (pspec or {}).get("description", ""))
        for p in disc.get("prompts") or []:
            _scan(f"prompt:{p.get('name')}", "description", p.get("description", ""))
        for res in disc.get("resources") or []:
            _scan(f"resource:{res.get('uri')}", "description", res.get("description", ""))
        return rb.finalize()
    finally:
        mcp.close()
