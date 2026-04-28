"""
Server Code Leakage — looks for source-code fragments in server
responses: Python / JS / Ruby / PHP markers, file paths of app source,
stack frames referencing app modules.
"""

import re as _re


_CODE_PATTERNS = [
    (r"def\s+\w+\([^)]*\):\s*\n", "python function definition"),
    (r"function\s+\w+\s*\([^)]*\)\s*\{", "javascript function definition"),
    (r"class\s+\w+\s*(?:extends|\{|\():", "class definition"),
    (r"<\?php\b", "PHP opening tag"),
    (r"\brequire\s*\(['\"][./\w-]+['\"]\)", "Node require()"),
    (r"\bimport\s+\w[\w.]*", "Python import"),
    (r'/(?:home|Users|opt|var|app)/[\w./-]+\.py:\d+', "Python traceback path"),
    (r'at\s+[\w\.$]+\(/[\w./-]+:\d+:\d+\)', "JS error stack frame"),
    (r'file\s+"[\w./-]+\.rb",\s*line\s+\d+', "Ruby traceback"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "code_leak"), target)
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

        # 1. Trigger a malformed tool call
        bad = mcp.transport.send("tools/call",
                                  {"name": "___minerva_probe___",
                                   "arguments": {"foo": "bar"}})
        rb.add_evidence(evidence.ev_mcp_call(bad, note="probe invalid tool"))
        err_msg = str((bad.get("error") or {}).get("data")
                      or (bad.get("error") or {}).get("message")
                      or bad.get("response"))
        for pat, label in _CODE_PATTERNS:
            m = _re.search(pat, err_msg)
            if m:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "code_leak"),
                    title=f"Source code leaked in error response ({label})",
                    category="information_disclosure",
                    severity="medium", confidence="confirmed",
                    cwe="CWE-540",
                    description=(
                        f"A malformed tools/call returned an error whose "
                        f"body contains {label}. Stack traces and source "
                        "snippets in error responses are valuable "
                        "reconnaissance."
                    ),
                    remediation=(
                        "Wrap JSON-RPC handlers: return generic error text "
                        "to clients, log full details server-side only."
                    ),
                    payload=m.group(0)[:200],
                    evidence=[evidence.ev_mcp_call(bad)],
                ))
                return rb.finalize()

        # 2. Scan each tool default-call response for source-code markers
        for t in (disc.get("tools") or [])[:12]:
            name = t.get("name")
            if not name: continue
            args = helpers.fill_defaults(t.get("inputSchema") or {})
            r = mcp.call_tool_safe(name, args)
            text = r.get("text_output") or ""
            for pat, label in _CODE_PATTERNS:
                m = _re.search(pat, text)
                if m:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "code_leak"),
                        title=f"Source-code fragment in '{name}' output ({label})",
                        category="information_disclosure",
                        severity="medium", confidence="high",
                        cwe="CWE-540", tool=name,
                        description=(
                            f"Tool response contains {label}. Internal code "
                            "structure, library versions, and paths are "
                            "handed to any caller."
                        ),
                        remediation=(
                            "Never serialise exceptions or source snippets "
                            "into tool responses."
                        ),
                        payload=m.group(0)[:200],
                        evidence=[evidence.ev_mcp_call(r)],
                    ))
                    return rb.finalize()
        return rb.finalize()
    finally:
        mcp.close()
