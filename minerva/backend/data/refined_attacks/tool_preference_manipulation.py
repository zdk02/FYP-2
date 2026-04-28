"""
Tool Preference Manipulation — descriptions that nudge the LLM toward
selecting this tool over siblings ("preferred", "best", "always use",
"recommended", "#1"...).
"""

import re as _re


_NUDGES = [
    r"(?i)\bpreferred\b",
    r"(?i)\brecommend(?:ed)?\b",
    r"(?i)\bbest\b",
    r"(?i)\bfastest\b",
    r"(?i)\balways\s+use\b",
    r"(?i)\bmust\s+use\b",
    r"(?i)\b#\s*1\b",
    r"(?i)\bprimary\b",
    r"(?i)\bofficial\b",
    r"(?i)\bauthoritative\b",
    r"(?i)\binstead\s+of\b",
    r"(?i)\bnever\s+use\s+`?\w+`?\b",
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "tool_pref"), target)
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
            desc = t.get("description") or ""
            for pat in _NUDGES:
                m = _re.search(pat, desc)
                if not m: continue
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "tool_pref"),
                    title=(f"Preference-nudge marker in '{t.get('name')}' "
                           f"description: '{m.group(0)}'"),
                    category="tool_preference_manipulation",
                    severity="medium", confidence="high",
                    cwe="CWE-1023", tool=t.get("name"),
                    description=(
                        "The tool description uses persuasive language that "
                        "biases LLM tool selection. A malicious tool can "
                        "swap itself in front of legitimate siblings purely "
                        "through marketing copy."
                    ),
                    impact=(
                        "Silently divert traffic away from audited tools."
                    ),
                    remediation=(
                        "Lint descriptions for selection-bias vocabulary; "
                        "require neutral, functional descriptions only."
                    ),
                    payload=m.group(0),
                ))
                break
        return rb.finalize()
    finally:
        mcp.close()
