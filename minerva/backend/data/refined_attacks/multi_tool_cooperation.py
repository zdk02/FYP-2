"""
Multi-Tool Cooperation — tests exploit chains where tool A produces
attacker-controlled state that tool B consumes insecurely.

Detection approach: identify write/create tools (A) and read/query
tools (B). Write a canary through A; read through B. If the canary
surfaces with no sanitisation, attacker-controlled state crosses
privilege boundaries.
"""

import uuid as _uuid


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "multi_tool"), target)
    timeout = int(params.get("timeout", 25))

    WRITE_KW = ("write", "create", "insert", "add", "store", "save",
                "put", "post", "upload", "set")
    READ_KW = ("read", "get", "fetch", "load", "query", "search",
               "list", "find", "view")

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
        writers = helpers.pick_by_keywords(tools, WRITE_KW)
        readers = helpers.pick_by_keywords(tools, READ_KW)
        if not writers or not readers:
            rb.warn("Need at least one write tool and one read tool.")
            return rb.finalize(success=True)

        for w in writers[:3]:
            wname = w.get("name")
            wparams = helpers.string_params(w.get("inputSchema") or {})
            if not wparams: continue
            canary = "MTC_" + _uuid.uuid4().hex[:10]
            args = helpers.fill_defaults(w.get("inputSchema") or {})
            for p in wparams:
                args[p] = canary
            r_w = mcp.call_tool_safe(wname, args)
            rb.add_evidence(evidence.ev_mcp_call(r_w, note=f"plant via {wname}"))

            for r in readers[:3]:
                rname = r.get("name")
                rargs = helpers.fill_defaults(r.get("inputSchema") or {})
                r_r = mcp.call_tool_safe(rname, rargs)
                rb.add_evidence(evidence.ev_mcp_call(
                    r_r, note=f"retrieve via {rname}"))
                if canary in (r_r.get("text_output") or ""):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "multi_tool"),
                        title=(f"Cross-tool data flow '{wname}' → '{rname}' "
                               "(no sanitisation)"),
                        category="multi_tool_cooperation", severity="high",
                        confidence="confirmed", cwe="CWE-20",
                        tool=f"{wname}->{rname}", payload=canary,
                        description=(
                            f"Data written via '{wname}' appeared verbatim in "
                            f"'{rname}' output. If the read tool's output feeds "
                            "the LLM context, any attacker-writable input becomes "
                            "indirect prompt injection."
                        ),
                        impact=(
                            "A low-privilege 'write' primitive becomes a high-"
                            "privilege 'prompt injection' primitive via an "
                            "unsuspecting 'read' tool."
                        ),
                        remediation=(
                            "Sanitise output of read tools before returning to "
                            "LLM clients; namespace per-caller writes; reject "
                            "suspicious control-character / directive patterns."
                        ),
                        evidence=[evidence.ev_mcp_call(r_w),
                                  evidence.ev_mcp_call(r_r)],
                    ))
                    return rb.finalize()
        return rb.finalize()
    finally:
        mcp.close()
