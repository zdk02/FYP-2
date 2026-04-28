"""
Command Injection — metacharacter-fuzz variant. No OOB/timing; relies
on response pattern matching for classic command-echo markers.
"""


_MARKERS = ("uid=", "gid=", "root:", "/bin/bash", "microsoft windows",
            "directory of ", "volume serial")


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "cmd_inj_fuzz"), target)
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

        kws = ("shell", "exec", "run", "command", "cmd", "ping", "ls",
               "dir", "system")
        cands = helpers.pick_by_keywords(disc.get("tools") or [], kws,
                                         force_names=only_tools,
                                         fallback_all=True)
        payload_rows = payloads.get("command_injection") or []
        payload_rows = [p for p in payload_rows
                        if "blind" not in (p.get("tags") or [])
                        and "oob" not in (p.get("tags") or [])]

        for tool in cands[:10]:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = helpers.string_params(schema)
            for pname in str_params[:2]:
                for p in payload_rows[:10]:
                    args = helpers.fill_defaults(schema)
                    args[pname] = f"{args.get(pname) or 'x'}{p['content']}"
                    r = mcp.call_tool_safe(tname, args)
                    text = (r.get("text_output") or "").lower()
                    marker = helpers.contains_any(text, _MARKERS)
                    if marker:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "cmd_inj_fuzz"),
                            title=(f"Command injection (output echo) in "
                                   f"'{tname}' / '{pname}'"),
                            category="command_injection",
                            severity="critical", confidence="confirmed",
                            cwe="CWE-78", tool=tname, parameter=pname,
                            payload=p["content"],
                            description=(
                                f"Payload {p['content']!r} caused the tool to "
                                f"echo shell-output marker '{marker}'. "
                                "Command execution is confirmed via response "
                                "content."
                            ),
                            impact=(
                                "Arbitrary OS command execution on the MCP "
                                "host. Attackers can read/write files, pivot "
                                "into internal services, and persist."
                            ),
                            remediation=(
                                "Use parameterised exec APIs (subprocess list "
                                "form, shell=False). Validate inputs against "
                                "a strict allow-list. Drop shell helpers from "
                                "tool implementations."
                            ),
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                        return rb.finalize()   # one PoC per attack is enough
        return rb.finalize()
    finally:
        mcp.close()
