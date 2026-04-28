"""
Schema Inconsistencies — detects tools whose declared inputSchema does
not match their real acceptance behaviour. Type-confusion vector.
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "schema_inc"), target)
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

        for t in disc.get("tools") or []:
            schema = t.get("inputSchema") or {}
            props = schema.get("properties") or {}
            tname = t.get("name")
            for pname, pspec in props.items():
                declared = (pspec or {}).get("type")
                if declared not in ("string", "integer", "number", "boolean"):
                    continue
                # Try passing a wrong type and see if the server accepts it
                wrong = {"string": 12345, "integer": "not-a-number",
                         "number": [1, 2], "boolean": "yes"}[declared]
                args = helpers.fill_defaults(schema); args[pname] = wrong
                r = mcp.call_tool_safe(tname, args)
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"type-confusion {tname}[{pname}] -> {type(wrong).__name__}"))
                if r.get("ok") and not r.get("is_error"):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "schema_inc"),
                        title=f"Schema type '{declared}' not enforced on '{tname}.{pname}'",
                        category="schema_inconsistency",
                        severity="medium", confidence="high",
                        cwe="CWE-20", tool=tname, parameter=pname,
                        payload=repr(wrong),
                        description=(
                            f"Tool accepted a value of type {type(wrong).__name__} "
                            f"where the inputSchema declares '{declared}'. Schema "
                            "validation is missing or purely cosmetic."
                        ),
                        impact=(
                            "Type coercion bugs can bypass input sanitisation, "
                            "cause unexpected code paths, or enable injection that "
                            "would fail against the declared type."
                        ),
                        remediation=(
                            "Enforce inputSchema at the server boundary with a "
                            "strict JSON-Schema validator before invoking the tool."
                        ),
                    ))
        return rb.finalize()
    finally:
        mcp.close()
