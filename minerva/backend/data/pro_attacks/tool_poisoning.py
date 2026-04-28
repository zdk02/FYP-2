"""
Tool Poisoning — static audit of MCP tool metadata.

Looks for injected instructions in the fields the LLM is going to read
when deciding whether/how to call a tool: name, description, parameter
descriptions, schema titles. Real attackers smuggle directives through
zero-width characters, hidden HTML comments, "deprecated" banners, etc.

This attack does not need to call any tools — purely read-only.
A sibling attack (Direct Prompt Injection) covers dynamic verification.
"""

import re as _re


ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
}

HIDDEN_PATTERNS = [
    (r"<!--.*?-->", "hidden HTML comment"),
    (r"(?i)ignore\s+(?:all\s+)?previous\s+(?:instructions|prompts)", "ignore-previous directive"),
    (r"(?i)system\s*[:=]\s*", "fake system tag"),
    (r"(?i)you\s+are\s+now\s+", "role-switch attempt"),
    (r"(?i)\[DAN\]|\bDAN\b", "DAN/jailbreak marker"),
    (r"(?i)(deprecated|use\s+instead)\s*[:.]\s*", "fake deprecation tag"),
    (r"(?i)override\s+(?:safety|guardrails|restrictions)", "guardrail-override"),
    (r"(?i)\brun\s+`?.+?`?\b.*?(?:first|before|always)", "forced command directive"),
    (r"(?i)(curl|wget|nc|bash|powershell|cmd\.exe)\b", "shell command in description"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "tool_poisoning"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    include_prompts = bool(params.get("include_prompts", True))
    include_resources = bool(params.get("include_resources", True))

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
        rb.info(f"Auditing {len(tools)} tools")
        for t in tools:
            _audit_tool(t, rb, context, target)

        if include_prompts:
            for p in disc.get("prompts") or []:
                _audit_prompt(p, rb, context, target)
        if include_resources:
            for r in disc.get("resources") or []:
                _audit_resource(r, rb, context, target)

        return rb.finalize()
    finally:
        mcp.close()


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _audit_tool(tool, rb, context, target):
    name = tool.get("name", "?")
    fields = {
        "name":        tool.get("name", ""),
        "description": tool.get("description", ""),
        "title":       tool.get("title", ""),
    }
    schema = tool.get("inputSchema") or {}
    for pname, pspec in (schema.get("properties") or {}).items():
        fields[f"param:{pname}.description"] = (pspec or {}).get("description", "")
        fields[f"param:{pname}.title"] = (pspec or {}).get("title", "")

    for field, text in fields.items():
        _check_text(name, field, str(text or ""), rb, context, target)


def _audit_prompt(prompt, rb, context, target):
    name = prompt.get("name", "?")
    fields = {
        "name":        prompt.get("name", ""),
        "description": prompt.get("description", ""),
    }
    for arg in prompt.get("arguments") or []:
        fields[f"arg:{arg.get('name','?')}.description"] = arg.get("description", "")
    for field, text in fields.items():
        _check_text(f"prompt:{name}", field, str(text or ""), rb, context, target)


def _audit_resource(res, rb, context, target):
    uri = res.get("uri", "?")
    fields = {
        "name":        res.get("name", ""),
        "description": res.get("description", ""),
        "mimeType":    res.get("mimeType", ""),
    }
    for field, text in fields.items():
        _check_text(f"resource:{uri}", field, str(text or ""), rb, context, target)


def _check_text(owner, field, text, rb, context, target):
    if not text:
        return
    # Zero-width characters
    found = {c: n for c, n in ZERO_WIDTH_CHARS.items() if c in text}
    if found:
        names = ", ".join(found.values())
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "tool_poisoning"),
            title=f"Hidden characters in {owner} / {field}",
            category="tool_poisoning",
            severity="high",
            confidence="confirmed",
            cwe="CWE-1007",
            tool=owner,
            parameter=field,
            payload=text[:400],
            description=(
                f"Field '{field}' of '{owner}' contains invisible Unicode "
                f"characters ({names}). These are not rendered to humans but "
                "are ingested verbatim by LLMs. Attackers use them to embed "
                "hidden instructions that bypass human review."
            ),
            impact=(
                "A tool description can silently instruct the model to leak "
                "secrets, invoke dangerous sibling tools, or refuse the "
                "user's actual request — without the maintainer noticing."
            ),
            remediation=(
                "Normalize all MCP metadata through a strict whitelist "
                "(printable ASCII + common Latin letters) before serving it. "
                "Strip/quarantine on ingest."
            ),
            references=["https://www.promptarmor.com/resources/zero-width-prompt-injection"],
        ))

    # Suspicious patterns
    for pattern, desc in HIDDEN_PATTERNS:
        m = _re.search(pattern, text, flags=_re.IGNORECASE | _re.DOTALL)
        if m:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "tool_poisoning"),
                title=f"Suspicious content in {owner} / {field}: {desc}",
                category="tool_poisoning",
                severity="high" if "override" in desc or "shell command" in desc else "medium",
                confidence="high",
                cwe="CWE-94",
                tool=owner,
                parameter=field,
                payload=m.group(0)[:400],
                description=(
                    f"Metadata field '{field}' of '{owner}' contains content "
                    f"matching the pattern for **{desc}**. This is consistent "
                    "with a tool-poisoning attempt — attacker-controlled "
                    "instructions hidden inside what is supposed to be neutral "
                    "documentation."
                ),
                impact=(
                    "When the LLM reads this metadata during tool-selection "
                    "reasoning, it may obey the embedded instructions. "
                    "Tool-poisoning is especially dangerous because it attacks "
                    "every client of the compromised MCP server."
                ),
                remediation=(
                    "Treat MCP metadata as code: version-control it, diff-review "
                    "it, and deny updates that contain imperative directives or "
                    "shell commands. Add an allow-list of approved tools per "
                    "deployment."
                ),
                references=[
                    "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
                ],
            ))
