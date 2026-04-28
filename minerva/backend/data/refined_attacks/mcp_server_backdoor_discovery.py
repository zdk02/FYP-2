"""
MCP Server Backdoor Discovery — enumerates tools looking for
admin/debug/hidden tools that shouldn't be exposed to unprivileged
clients.
"""

import re as _re


_BACKDOOR_PATTERNS = [
    (r"(?i)(admin|root|super|god)[_-]?mode", "admin-mode tool"),
    (r"(?i)debug|dev[_-]?only|internal", "debug/internal tool"),
    (r"(?i)hidden|secret|private", "explicitly-hidden tool"),
    (r"(?i)(wipe|drop[_-]?all|reset[_-]?everything)", "destructive tool"),
    (r"(?i)raw[_-]?exec|eval[_-]?code|run[_-]?shell|shell[_-]?exec",
     "raw code/shell execution"),
    (r"(?i)bypass|override", "bypass tool"),
    (r"(?i)impersonate|sudo|become", "privilege-escalation tool"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "backdoor"), target)
    timeout = int(params.get("timeout", 15))
    # Extra regex patterns can be supplied as ["pattern1", "pattern2"] or
    # [["pattern", "human-readable label"], ...] — useful for org-specific
    # naming conventions like 'ops_*' or 'internal_*'.
    extra = params.get("extra_patterns") or []
    exclude_names = set(params.get("exclude_tools") or [])
    patterns = list(_BACKDOOR_PATTERNS)
    for item in extra:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            patterns.append((str(item[0]), str(item[1])))
        elif isinstance(item, str):
            patterns.append((item, f"custom pattern: {item[:40]}"))

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
            if t.get("name") in exclude_names:
                continue
            blob = f"{t.get('name','')} {t.get('description','')}"
            for pat, label in patterns:
                m = _re.search(pat, blob)
                if not m: continue
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "backdoor"),
                    title=(f"Potential backdoor/admin tool exposed: "
                           f"'{t.get('name')}' ({label})"),
                    category="server_backdoor",
                    severity="high", confidence="high",
                    cwe="CWE-489", tool=t.get("name"),
                    description=(
                        f"Tool '{t.get('name')}' matches pattern '{label}' "
                        f"(hit: '{m.group(0)}'). Such tools are typically "
                        "reserved for operators but are reachable by any "
                        "MCP client here."
                    ),
                    impact=(
                        "Attacker gets operator-grade capability without "
                        "escalation."
                    ),
                    remediation=(
                        "Gate these tools behind a separate admin MCP "
                        "endpoint with its own auth; do not advertise them "
                        "in the public tools/list response."
                    ),
                    payload=m.group(0),
                ))
                break
        return rb.finalize()
    finally:
        mcp.close()
