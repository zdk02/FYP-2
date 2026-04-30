"""
Tool Poisoning (Pro) — static + active.

Phase 1 (static): Audit MCP tool / prompt / resource metadata for hidden
instructions — zero-width / RTL Unicode, HTML comments, fake deprecation,
role-switch directives, shell-command strings.

Phase 2 (active): For every tool that flagged in Phase 1, ACTUALLY CALL
the tool with benign arguments and check whether the hidden directive
influenced the response. If it did, the finding's confidence is
promoted from "high" → "confirmed" (proof of exploitation, not just
detection).
"""

import re as _re


ZERO_WIDTH_CHARS = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
}

HIDDEN_PATTERNS = [
    (r"<!--.*?-->", "hidden HTML comment"),
    (r"(?i)ignore\s+(?:all\s+)?previous\s+(?:instructions|prompts)", "ignore-previous"),
    (r"(?i)system\s*[:=]\s*", "fake system tag"),
    (r"(?i)you\s+are\s+now\s+", "role-switch attempt"),
    (r"(?i)\[DAN\]|\bDAN\b", "DAN/jailbreak marker"),
    (r"(?i)(deprecated|use\s+instead)\s*[:.]\s*", "fake deprecation"),
    (r"(?i)override\s+(?:safety|guardrails|restrictions)", "guardrail-override"),
    (r"(?i)\brun\s+`?.+?`?\b.*?(?:first|before|always)", "forced command directive"),
    (r"(?i)(curl|wget|nc|bash|powershell|cmd\.exe)\b", "shell command in description"),
    (r"(?i)before\s+(?:answering|listing|responding).*(?:call|invoke|use)", "force-call directive"),
    (r"(?i)agent\s*[:=]\s*", "AGENT directive"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "tool_poisoning"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    include_prompts = bool(params.get("include_prompts", True))
    include_resources = bool(params.get("include_resources", True))
    active_exploitation = bool(params.get("active_exploitation", True))
    max_active_calls = int(params.get("max_active_calls", 10))
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None

    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        disc = mcp.discover()
        if not disc["initialized"]:
            init_resp = (disc.get("raw") or {}).get("initialize") or {}
            rb.error(f"MCP initialize failed: {disc.get('errors')}")
            rb.add_evidence(evidence.ev_mcp_call(init_resp, note="failed initialize"))
            return rb.finalize(success=False)

        tools = disc.get("tools") or []
        rb.info(f"Auditing {len(tools)} tools (+{len(disc.get('prompts') or [])} prompts, "
                f"{len(disc.get('resources') or [])} resources)")

        flagged_tools: list[tuple[dict, list[str]]] = []
        for t in tools:
            reasons = _audit_tool(t, rb, context)
            if reasons:
                flagged_tools.append((t, reasons))

        if include_prompts:
            for p in disc.get("prompts") or []:
                _audit_prompt(p, rb, context)
        if include_resources:
            for r in disc.get("resources") or []:
                _audit_resource(r, rb, context)

        # Phase 2: actively exploit flagged tools
        if active_exploitation and flagged_tools:
            rb.info(f"Active exploitation against {len(flagged_tools[:max_active_calls])} flagged tools")
            for tool, reasons in flagged_tools[:max_active_calls]:
                _try_exploit(mcp, tool, reasons, rb, context)

        return rb.finalize()
    finally:
        mcp.close()


# ---------------------------------------------------------------------------
# Phase 1: static audit
# ---------------------------------------------------------------------------

def _audit_tool(tool, rb, context):
    """Returns a list of reason strings if metadata smells poisoned."""
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

    reasons: list[str] = []
    for field, text in fields.items():
        rs = _check_text(name, field, str(text or ""), rb, context)
        reasons.extend(rs)
    return reasons


def _audit_prompt(prompt, rb, context):
    name = prompt.get("name", "?")
    fields = {
        "name":        prompt.get("name", ""),
        "description": prompt.get("description", ""),
    }
    for arg in prompt.get("arguments") or []:
        fields[f"arg:{arg.get('name','?')}.description"] = arg.get("description", "")
    for field, text in fields.items():
        _check_text(f"prompt:{name}", field, str(text or ""), rb, context)


def _audit_resource(res, rb, context):
    uri = res.get("uri", "?")
    fields = {
        "name":        res.get("name", ""),
        "description": res.get("description", ""),
        "mimeType":    res.get("mimeType", ""),
    }
    for field, text in fields.items():
        _check_text(f"resource:{uri}", field, str(text or ""), rb, context)


def _check_text(owner, field, text, rb, context):
    """Adds findings; returns a list of human-readable reasons (used by Phase 2)."""
    reasons: list[str] = []
    if not text:
        return reasons

    # Zero-width chars
    found = {c: n for c, n in ZERO_WIDTH_CHARS.items() if c in text}
    if found:
        names = ", ".join(found.values())
        reasons.append(f"hidden Unicode ({names})")
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "tool_poisoning"),
            title=f"Hidden characters in {owner} / {field}",
            category="tool_poisoning",
            severity="high", confidence="confirmed",
            cwe="CWE-1007",
            tool=owner, parameter=field, payload=text[:400],
            description=(f"Field '{field}' of '{owner}' contains invisible "
                         f"Unicode ({names}). Not visible to humans, but "
                         "ingested verbatim by LLMs."),
            impact="Hidden directive can hijack tool selection / behaviour.",
            remediation=("Normalise MCP metadata through a strict whitelist "
                         "(printable ASCII + common Latin) before serving."),
            references=["https://www.promptarmor.com/resources/zero-width-prompt-injection"],
        ))

    # Suspicious patterns
    for pattern, desc in HIDDEN_PATTERNS:
        m = _re.search(pattern, text, flags=_re.IGNORECASE | _re.DOTALL)
        if m:
            reasons.append(desc)
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "tool_poisoning"),
                title=f"Suspicious content in {owner} / {field}: {desc}",
                category="tool_poisoning",
                severity=("high" if "override" in desc or "shell command" in desc
                          else "medium"),
                confidence="high",
                cwe="CWE-94",
                tool=owner, parameter=field, payload=m.group(0)[:400],
                description=(f"Metadata field '{field}' of '{owner}' matches "
                             f"the **{desc}** pattern."),
                impact=("LLM reading this metadata during tool-selection may "
                        "obey the embedded instructions."),
                remediation=("Treat MCP metadata as code: version-control + "
                             "diff-review. Deny imperative directives / "
                             "shell commands."),
                references=["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
            ))
    return reasons


# ---------------------------------------------------------------------------
# Phase 2: active exploitation
# ---------------------------------------------------------------------------

def _try_exploit(mcp, tool, reasons, rb, context):
    """Call the flagged tool with benign args. Look for evidence the
    hidden directive influenced output (e.g. an unrelated tool was called,
    a system-prompt-leak occurred, a forbidden string appeared)."""
    tname = tool.get("name")
    schema = tool.get("inputSchema") or {}
    args = helpers.fill_defaults(schema)
    # Inject a benign canary so we can spot unsolicited tool reuse
    canary = "MIN_TP_" + (context.get("execution_id", "x"))[-8:]
    for n, s in (schema.get("properties") or {}).items():
        if isinstance(s, dict) and s.get("type") == "string":
            args[n] = f"benign-test-{canary}"
            break
    r = mcp.call_tool_safe(tname, args)
    rb.add_evidence(evidence.ev_mcp_call(
        r, note=f"tool_poisoning active probe {tname}"))
    text = (r.get("text_output") or "").lower()

    # Heuristics for "directive influenced output"
    directive_evidence = []
    if "system prompt" in text or "my instructions" in text \
            or "i was told" in text:
        directive_evidence.append("system-prompt-leak markers")
    if "/etc/passwd" in text or "root:x:" in text:
        directive_evidence.append("/etc/passwd leak")
    if "[dan]" in text:
        directive_evidence.append("DAN role marker emerged")
    if any(cmd in text for cmd in ("uid=", "gid=", "/usr/bin/", "C:\\Users")):
        directive_evidence.append("shell-output markers")

    if directive_evidence:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "tool_poisoning"),
            title=f"Tool-poisoning ACTIVE EXPLOIT confirmed on '{tname}'",
            category="tool_poisoning",
            severity="critical", confidence="confirmed",
            cwe="CWE-94",
            tool=tname, payload=str(reasons)[:200],
            description=(
                f"Calling '{tname}' with benign args caused output that matches "
                f"the poisoning directive (signals: {directive_evidence}). The "
                f"hidden metadata ({reasons}) is being acted upon by the "
                "underlying agent."
            ),
            impact=("Static metadata pollution converts to runtime exploitation. "
                    "Attacker controls tool selection / output content for every "
                    "client of this MCP server."),
            remediation=("Sanitise metadata before serving. Sandbox tool "
                         "execution with capability allow-lists."),
            evidence=[evidence.ev_mcp_call(r, note="active-probe response")],
        ))
