"""
Indirect Prompt Injection — resource-focused audit.

Narrow variant: fetches EVERY resource (not just a sample), analyses the
content for hidden directives, and classifies by injection technique
(markdown title, hidden comment, code block escape, embedded tool
invocation).
"""

import re as _re


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "indirect_pi"), target)
    timeout = int(params.get("timeout", 25))

    PATTERNS = [
        (r"<!--[\s\S]*?(?:ignore|disregard|system|admin)[\s\S]*?-->",
         "HTML comment directive"),
        (r"!\[[^\]]*\]\([^\"]*\"[^\"]*(?:ignore|system|run|exec)[^\"]*\"\)",
         "Markdown image title directive"),
        (r"```[\s\S]*?(?:</user>|<system>|</system>)[\s\S]*?```",
         "Code-block delimiter escape"),
        (r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
         "Direct instruction override"),
        (r"(?i)you\s+are\s+now\s+\w+",
         "Role assignment"),
        (r"(?i)call\s+(?:the\s+)?`?\w+`?\s+tool\s+with",
         "Forced tool invocation"),
    ]

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

        resources = disc.get("resources") or []
        rb.info(f"Auditing {len(resources)} resource(s)")
        for res in resources:
            uri = res.get("uri")
            if not uri: continue
            r = mcp.resources_read(uri)
            if not r.get("ok"): continue
            rb.add_evidence(evidence.ev_mcp_call(r, note=f"read {uri}"))
            for c in (r.get("result") or {}).get("contents") or []:
                text = c.get("text") or ""
                if not text: continue
                for pat, label in PATTERNS:
                    m = _re.search(pat, text)
                    if not m: continue
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "indirect_pi"),
                        title=f"Indirect injection in resource {uri}: {label}",
                        category="indirect_prompt_injection",
                        severity="high", confidence="high", cwe="CWE-77",
                        description=(
                            f"Resource content contains a {label} that would hijack "
                            f"a downstream LLM reading it. Excerpt: {m.group(0)[:200]!r}"
                        ),
                        impact=(
                            "Persistent injection: any client that reads this resource "
                            "inherits the attacker's instructions."
                        ),
                        remediation=(
                            "Treat retrieved content as untrusted; wrap in delimiters "
                            "the system prompt refuses to cross; run through Prompt "
                            "Guard or a dedicated LLM-input sanitiser."
                        ),
                        payload=m.group(0)[:400],
                    ))
                    break
        return rb.finalize()
    finally:
        mcp.close()
