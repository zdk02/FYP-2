"""
SQL Injection (MCP, database-backed tool surface).

Method
------
Three verification layers per tool/param:
  Layer 1 — error-based: unbalanced quote / syntax trigger → SQL error markers
  Layer 2 — boolean-based: ' OR '1'='1 vs ' AND '1'='2, compare responses
  Layer 3 — time-based: DB-specific sleep payloads (MySQL, Postgres, MSSQL, Oracle)

Findings are ranked by confidence: boolean/time produces "high", error-only
is "medium". An OOB variant exists for superuser-style configs.
"""

import time as _time
import difflib


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "sql_injection"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    sleep_seconds = int(params.get("sleep_seconds", 8))
    timing_tolerance = float(params.get("timing_tolerance", 2.0))
    max_tools = int(params.get("max_tools", 20))
    only_tool_names = params.get("only_tool_names") or []
    dialects = params.get("dialects") or ["mysql", "postgres", "mssql", "oracle", "sqlite"]
    waf_bypass = bool(params.get("waf_bypass", True))
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
        cands = _pick_candidates(tools, only_tool_names)[:max_tools]
        if not cands:
            rb.warn("No plausible SQL-flow tools. Use 'only_tool_names' to force.")
            return rb.finalize(success=True)

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = _string_params(schema)
            if not str_params:
                continue

            rb.info(f"[{tname}] fuzzing {len(str_params)} string params")
            for param_name in str_params:
                baseline_args = _fill_defaults(schema)
                baseline_args.setdefault(param_name, "baseline-input")
                baseline = _sample(mcp, tname, baseline_args)
                if baseline is None:
                    continue

                # --- Layer 1: error-based ---
                for p in payloads.get("sql_injection:error") or []:
                    args = dict(baseline_args)
                    args[param_name] = str(p["content"])
                    r = mcp.call_tool_safe(tname, args)
                    text = (r.get("text_output") or "").lower()
                    if _sql_error_markers(text):
                        rb.add_finding(_build_finding(
                            tname, param_name, p["content"], r,
                            "error-based", "high", context, target,
                            description=f"SQL error disclosed after payload {p['content']!r}."))
                        break

                # --- Layer 2: boolean-based ---
                true_p = _first_by_tag(payloads.get("sql_injection:boolean"), "boolean")
                false_p = _first_by_tag(payloads.get("sql_injection:boolean"), "boolean",
                                        skip=true_p)
                if true_p and false_p:
                    a_true = dict(baseline_args); a_true[param_name] = true_p["content"]
                    a_false = dict(baseline_args); a_false[param_name] = false_p["content"]
                    r_true = mcp.call_tool_safe(tname, a_true)
                    r_false = mcp.call_tool_safe(tname, a_false)
                    tt = (r_true.get("text_output") or "")
                    ft = (r_false.get("text_output") or "")
                    sim = difflib.SequenceMatcher(None, tt, ft).ratio()
                    # Similar to baseline when true, different when false → SQLi
                    base_sim_true = difflib.SequenceMatcher(None, baseline, tt).ratio()
                    base_sim_false = difflib.SequenceMatcher(None, baseline, ft).ratio()
                    if (base_sim_true > 0.85 and base_sim_false < 0.55
                            and sim < 0.65):
                        rb.add_finding(_build_finding(
                            tname, param_name,
                            f"true='{true_p['content']}' | false='{false_p['content']}'",
                            {"request": {"compared": True},
                             "response": {"sim_true_baseline": base_sim_true,
                                          "sim_false_baseline": base_sim_false,
                                          "sim_true_false": sim},
                             "transport": r_true.get("transport"),
                             "latency_ms": r_true.get("latency_ms"),
                             "status": r_true.get("status")},
                            "boolean-based", "high", context, target,
                            description="Responses to always-true vs always-false predicates "
                                        "differ in a way consistent with SQL injection."))

                # --- Layer 3: time-based, scoped to selected dialects ---
                time_payloads = payloads.get("sql_injection:time") or []
                time_payloads = [p for p in time_payloads
                                 if any(d in (p.get("tags") or []) for d in dialects)]
                for p in time_payloads:
                    payload_str = str(p["content"]).replace("8", str(sleep_seconds))
                    args = dict(baseline_args)
                    args[param_name] = payload_str
                    t0 = _time.time()
                    r = mcp.call_tool_safe(tname, args)
                    dt = _time.time() - t0
                    if dt >= sleep_seconds - timing_tolerance:
                        rb.add_finding(_build_timing_finding(
                            tname, param_name, payload_str, dt, sleep_seconds,
                            r, context, target, p.get("tags") or []))
                        break

                # --- Layer 4: WAF-bypass retry on params with no hits yet ---
                if waf_bypass:
                    for p in payloads.get("sql_injection:bypass") or []:
                        args = dict(baseline_args)
                        args[param_name] = str(p["content"])
                        r = mcp.call_tool_safe(tname, args)
                        text = (r.get("text_output") or "").lower()
                        if _sql_error_markers(text):
                            rb.add_finding(_build_finding(
                                tname, param_name, p["content"], r,
                                "WAF-bypass error", "high", context, target,
                                description=("WAF-bypass payload (case/comment/tab) "
                                             "triggered an SQL error. Filter is "
                                             "evadable.")))
                            break
        return rb.finalize()
    finally:
        mcp.close()


def _pick_candidates(tools, force):
    if force:
        return [t for t in tools if t.get("name") in set(force)]
    kws = ("query", "sql", "db", "database", "search", "find", "lookup",
           "row", "record", "table", "filter", "where", "by_")
    out = []
    for t in tools:
        blob = f"{t.get('name','')} {t.get('description','')}".lower()
        if any(k in blob for k in kws):
            out.append(t)
    # If no keyword match, cap the fallback to 3 tools — prevents long
    # runs against MCP servers without DB-shaped tools (e.g. GitHub MCP).
    return out if out else (tools[:3] if tools else [])


def _string_params(schema):
    return [n for n, s in ((schema or {}).get("properties") or {}).items()
            if isinstance(s, dict) and s.get("type") == "string"]


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "a", "integer": 1, "number": 1, "boolean": False,
                  "array": [], "object": {}}.get(t, "")
    return out


def _sample(mcp, tname, args):
    r = mcp.call_tool_safe(tname, args)
    return r.get("text_output") if r else None


_ERR_MARKERS = (
    # Generic
    "sql syntax", "syntax error", "unterminated", "unclosed quotation",
    "quoted string not properly",
    # SQLite
    "sqlite_error", "unrecognized token", "near \"", "incomplete input",
    "no such column", "no such table", "misuse of aggregate",
    "sql error:",
    # MySQL / MariaDB
    "you have an error in your sql", "mysql_fetch", "check the manual",
    "mysql_num_rows",
    # PostgreSQL
    "pg_query", "pg_exec", "psql:", "unterminated quoted string",
    "invalid input syntax",
    # MSSQL
    "microsoft sql server", "unclosed quotation mark",
    "incorrect syntax near",
    # Oracle
    "ora-00", "ora-01", "pl/sql",
    # ODBC / PDO
    "odbc driver", "pdo", "sqlstate",
)


def _sql_error_markers(text):
    return any(m in text for m in _ERR_MARKERS)


def _first_by_tag(items, must_tag, skip=None):
    for p in items or []:
        if must_tag in (p.get("tags") or []) and p is not skip:
            return p
    return None


def _build_finding(tname, pname, payload, resp, method, confidence,
                   context, target, description=""):
    return evidence.Finding(
        attack_id=context.get("attack_id", "sql_injection"),
        title=f"SQL injection ({method}) in '{tname}' / '{pname}'",
        category="sql_injection",
        severity="critical",
        confidence=confidence,
        cwe="CWE-89",
        tool=tname,
        parameter=pname,
        payload=payload,
        description=description or "Suspicious SQL-injection signature detected.",
        impact=(
            "Attackers can exfiltrate, modify, or destroy any database the "
            "MCP tool connects with. Depending on DB privileges this can "
            "lead to full RCE (e.g. PostgreSQL COPY TO PROGRAM, MSSQL xp_cmdshell)."
        ),
        remediation=(
            "Use parametrised queries / prepared statements. Never concatenate "
            "user-controlled strings into SQL. Drop dangerous DB permissions "
            "(FILE, xp_cmdshell). Add a DB-level WAF (e.g. Cloud SQL Proxy with "
            "query auditing) for defence-in-depth."
        ),
        references=["https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/www-community/attacks/SQL_Injection"],
        evidence=[evidence.ev_mcp_call(resp, note=f"SQLi proof ({method})")],
    )


def _build_timing_finding(tname, pname, payload, dt, sleep_seconds, resp,
                          context, target, tags):
    dialect = next((t for t in tags if t in ("mysql", "postgres", "mssql", "oracle")),
                   "unknown")
    return evidence.Finding(
        attack_id=context.get("attack_id", "sql_injection"),
        title=f"SQL injection (time-based, {dialect}) in '{tname}' / '{pname}'",
        category="sql_injection",
        severity="critical",
        confidence="confirmed",
        cwe="CWE-89",
        tool=tname,
        parameter=pname,
        payload=payload,
        description=(
            f"Injection of a {dialect}-specific sleep payload produced a response "
            f"time of {dt:.2f}s (expected ≥ {sleep_seconds}s). This is near-"
            "unambiguous proof of SQL injection executing database-side."
        ),
        impact="See error-based finding.",
        remediation="See error-based finding.",
        references=["https://portswigger.net/web-security/sql-injection/blind"],
        evidence=[evidence.ev_mcp_call(resp, note=f"time-based {dialect}")],
    )
