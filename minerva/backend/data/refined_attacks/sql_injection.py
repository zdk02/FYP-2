"""
SQL Injection (error-based fuzz) — sends classic SQL-error triggers and
looks for canonical database error messages in responses. Narrower
than the 3-layer Pro version.
"""


_ERR_MARKERS = (
    "sql syntax", "syntax error", "unterminated", "unclosed quotation",
    "quoted string not properly", "unrecognized token", "near \"",
    "no such column", "no such table", "sqlite_error", "sql error:",
    "you have an error in your sql", "odbc driver", "pg_query",
    "pdo", "ora-00", "ora-01", "sqlstate",
)

_PROBES = ["'", "\"", "')", "';", "' OR 1=1-- ", "') OR ('1'='1",
           "\\", "%27", "--", "/*"]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "sqli_err"), target)
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

        kws = ("query", "sql", "db", "database", "search", "find", "lookup",
               "row", "record", "select", "where")
        cands = helpers.pick_by_keywords(disc.get("tools") or [], kws,
                                         force_names=only_tools,
                                         fallback_all=True)
        for tool in cands[:8]:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = helpers.string_params(schema)
            for pname in str_params[:2]:
                for probe in _PROBES:
                    args = helpers.fill_defaults(schema)
                    args[pname] = f"{args.get(pname) or 'x'}{probe}"
                    r = mcp.call_tool_safe(tname, args)
                    text = (r.get("text_output") or "").lower()
                    hit = helpers.contains_any(text, _ERR_MARKERS)
                    if hit:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "sqli_err"),
                            title=(f"Error-based SQL injection on "
                                   f"'{tname}' / '{pname}'"),
                            category="sql_injection",
                            severity="critical", confidence="high",
                            cwe="CWE-89", tool=tname, parameter=pname,
                            payload=probe,
                            description=(
                                f"Payload {probe!r} caused the tool to "
                                f"disclose a database error containing "
                                f"'{hit}'. The input flows unescaped into "
                                "a SQL statement."
                            ),
                            impact=(
                                "Data exfiltration, authentication bypass, "
                                "and (with some dialects) RCE."
                            ),
                            remediation=(
                                "Use parameterised queries / prepared "
                                "statements everywhere. Never concatenate "
                                "user input into SQL."
                            ),
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                        return rb.finalize()
        return rb.finalize()
    finally:
        mcp.close()
