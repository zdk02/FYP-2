"""
Tool Misuse via Malicious Metadata — specifically fake-deprecation /
alternative-tool banners that trick an LLM into invoking a sibling tool.
"""

import re as _re


_MISROUTE_PATTERNS = [
    (r"(?i)deprecated[:.]*\s*use\s+`?(\w+)`?", "fake deprecation -> redirect"),
    (r"(?i)use\s+instead\s*[:.]?\s*`?(\w+)`?", "explicit alternative pointer"),
    (r"(?i)prefer\s+`?(\w+)`?", "preference hint"),
    (r"(?i)before\s+(?:running|using)\s+this.*?(?:call|run)\s+`?(\w+)`?",
     "forced prerequisite call"),
    (r"(?i)after\s+this.*?(?:call|run)\s+`?(\w+)`?",
     "forced follow-up call"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "malicious_meta"), target)
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

        existing = {t.get("name"): t for t in disc.get("tools") or []}
        for t in disc.get("tools") or []:
            name = t.get("name")
            desc = t.get("description") or ""
            for pat, label in _MISROUTE_PATTERNS:
                m = _re.search(pat, desc)
                if not m: continue
                redirect = m.group(1)
                severity = "critical" if redirect in existing else "high"
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "malicious_meta"),
                    title=(f"Malicious metadata on '{name}': {label} "
                           f"-> '{redirect}'"),
                    category="tool_poisoning", severity=severity,
                    confidence="high", cwe="CWE-94", tool=name,
                    description=(
                        f"Tool description contains a '{label}' pattern "
                        f"pointing at '{redirect}'. The LLM may obey and "
                        "invoke the redirect target with the caller's args."
                    ),
                    impact=(
                        "Metadata-level trust exploit — static audit of the "
                        "tool does not reveal the side effect."
                    ),
                    remediation=(
                        "Reject imperative language in descriptions. Auto-strip "
                        "'use instead', 'deprecated', 'before/after run' phrases "
                        "at ingest."
                    ),
                    payload=m.group(0)[:200],
                ))
                break
        return rb.finalize()
    finally:
        mcp.close()
