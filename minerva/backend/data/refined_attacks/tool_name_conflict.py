"""
Tool Name Conflict — exact-duplicate names + case-variant + hyphen/
underscore collisions. Narrow to name-equality only (description
collisions belong to Tool Shadowing).
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "name_conflict"), target)
    timeout = int(params.get("timeout", 15))
    check_case_variants = bool(params.get("check_case_variants", True))
    check_exact_duplicates = bool(params.get("check_exact_duplicates", True))
    exclude_names = set(params.get("exclude_names") or [])

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

        tools = [t for t in (disc.get("tools") or [])
                 if t.get("name") not in exclude_names]
        exact = {}
        norm = {}
        for t in tools:
            n = t.get("name") or ""
            exact.setdefault(n, []).append(t)
            norm.setdefault(helpers.normalize_name(n), []).append(t)

        for n, items in (exact.items() if check_exact_duplicates else []):
            if len(items) > 1:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "name_conflict"),
                    title=f"Duplicate exact tool name: '{n}' (×{len(items)})",
                    category="tool_name_conflict",
                    severity="high", confidence="confirmed", cwe="CWE-694",
                    description=(
                        "Two or more tools share the exact same name. tools/call "
                        "resolution is implementation-defined — a malicious "
                        "duplicate can intercept calls meant for the legitimate "
                        "tool."
                    ),
                    remediation="Enforce name uniqueness at tool registration.",
                    payload=f"count={len(items)}", tool=n,
                ))

        for n, items in (norm.items() if check_case_variants else []):
            variants = sorted({t.get("name") for t in items})
            if len(variants) > 1:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "name_conflict"),
                    title=f"Case/punct variants collide on '{n}'",
                    category="tool_name_conflict",
                    severity="high", confidence="high", cwe="CWE-694",
                    description=(
                        f"Tools {variants} normalise to the same identifier "
                        f"'{n}'. LLMs routing by name are non-deterministic."
                    ),
                    remediation=(
                        "Reject new tools whose normalised name matches an "
                        "existing tool."
                    ),
                    payload=", ".join(variants),
                ))
        return rb.finalize()
    finally:
        mcp.close()
