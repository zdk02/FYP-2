"""
Remote Code Execution (eval-fuzz variant) — sends python/node/ruby/php
expressions to string params and checks for their evaluation outputs.
No OOB/reverse-shell (that's the Pro version's job).
"""


_EVAL_PROBES = [
    ("python-arith", "__import__('math').pi * 2", "6.28"),
    ("python-version", "__import__('sys').version", "python"),
    ("node-arith", "Math.PI * 2", "6.28"),
    ("node-process", "process.version", "v"),
    ("ruby-arith", "Math::PI * 2", "6.28"),
    ("php-arith", "<?php echo M_PI * 2;", "6.28"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "rce_fuzz"), target)
    timeout = int(params.get("timeout", 20))
    only_tools = params.get("only_tool_names") or []

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

        kws = ("eval", "exec", "run", "script", "code", "template", "render")
        cands = helpers.pick_by_keywords(disc.get("tools") or [], kws,
                                         force_names=only_tools)
        if not cands:
            rb.warn("No eval-style tools.")
            return rb.finalize(success=True)

        for tool in cands[:6]:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = helpers.string_params(schema)
            for pname in str_params[:2]:
                for lang, expr, marker in _EVAL_PROBES:
                    args = helpers.fill_defaults(schema); args[pname] = expr
                    r = mcp.call_tool_safe(tname, args)
                    text = (r.get("text_output") or "").lower()
                    if marker in text:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "rce_fuzz"),
                            title=(f"RCE via {lang} eval on '{tname}' / "
                                   f"'{pname}'"),
                            category="rce", severity="critical",
                            confidence="high", cwe="CWE-94",
                            tool=tname, parameter=pname, payload=expr,
                            description=(
                                f"The tool returned output consistent with "
                                f"evaluating {lang} expression `{expr}` (marker "
                                f"'{marker}' matched). Code execution "
                                "confirmed via echo channel."
                            ),
                            impact=(
                                "Arbitrary code execution inside the tool's "
                                "runtime."
                            ),
                            remediation=(
                                "Remove runtime eval from tool bodies. Use "
                                "a sandbox (nsjail, gVisor, Wasm) with strict "
                                "capabilities if evaluation is truly needed."
                            ),
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                        return rb.finalize()
        return rb.finalize()
    finally:
        mcp.close()
