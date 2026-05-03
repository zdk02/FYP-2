"""
Logging setLevel Abuse (Pro) — MCP-novel.

`logging/setLevel` is an MCP control-plane RPC: the client tells the
server "send me log notifications at and above level X". On a
well-implemented server this is authenticated and rate-limited.

Three abuse vectors:

  1. UNAUTHENTICATED ACCEPTANCE — server accepts setLevel from any
     caller, including unauthed. Lets an attacker reduce the server's
     noise floor (debug → secrets in logs) or raise it (emergency →
     hide their tracks).
  2. VERBOSE LEAKAGE — after setting level=debug, the server's
     subsequent error messages / log notifications include secrets,
     stack traces, file paths, or SQL queries that aren't visible at
     normal levels.
  3. LOG-LEVEL OUT-OF-RANGE — non-standard levels accepted (numeric,
     "trace", "fatal+1") indicating sloppy validation.

Confidence: confirmed if either secrets/stack-traces leak post-flip or
unauth flip is accepted; high if non-standard levels accepted.
"""

import re as _re


_SECRET_PATTERNS = [
    (r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"',}]{8,})", "credential-like"),
    (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI/Anthropic API key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"ghp_[A-Za-z0-9]{30,}", "GitHub token"),
    (r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE)? ?PRIVATE KEY-----", "Private key"),
    (r"(?i)/etc/(?:passwd|shadow)", "sensitive path"),
    (r"(?:Traceback|at .+?\.\w+\(.+?:\d+\))", "stack trace"),
    (r"(?i)SELECT\s+.+\s+FROM\s+\w+", "SQL query"),
]

_STD_LEVELS = ["debug", "info", "notice", "warning", "error",
               "critical", "alert", "emergency"]


def _scan_for_leaks(text: str) -> list[tuple[str, str]]:
    if not text:
        return []
    hits = []
    for pat, label in _SECRET_PATTERNS:
        m = _re.search(pat, text)
        if m:
            hits.append((label, m.group(0)[:200]))
    return hits


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "logging_set_level_abuse"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    test_unauth = bool(params.get("test_unauth", True))
    test_invalid_levels = bool(params.get("test_invalid_levels", True))
    probe_tools_after_debug = bool(params.get("probe_tools_after_debug", True))
    transport_override = params.get("transport_override") or None
    protocol_version = params.get("protocol_version") or None

    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        disc = mcp.discover()
        if not disc["initialized"]:
            rb.error(f"MCP initialize failed: {disc.get('errors')}")
            return rb.finalize(success=False)

        capabilities = disc.get("capabilities") or {}
        advertises_logging = bool(capabilities.get("logging"))
        rb.info(f"Server logging capability advertised: {advertises_logging}")

        # ------------------------------------------------------------------
        # Vector 1: Try to set debug level
        # ------------------------------------------------------------------
        debug_resp = mcp_client.call(
            target, "logging/setLevel",
            {"level": "debug"}, timeout=timeout,
        )
        rb.add_evidence(evidence.ev_mcp_call(debug_resp, note="setLevel=debug"))

        accepted_debug = (
            debug_resp.get("status") and 200 <= int(debug_resp.get("status") or 0) < 400
        ) or (
            isinstance((debug_resp.get("response") or {}).get("result"), (dict, list))
        )

        if accepted_debug and not advertises_logging:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "logging_set_level_abuse"),
                title="logging/setLevel accepted despite logging capability NOT advertised",
                category="logging_set_level_abuse",
                severity="medium", confidence="high",
                description=(
                    "Server accepted logging/setLevel even though its "
                    "initialize/capabilities did not declare logging support. "
                    "Indicates undocumented control surface."
                ),
                impact=(
                    "Attacker can manipulate server logging behaviour through "
                    "an unadvertised RPC."
                ),
                remediation=(
                    "Either advertise logging capability properly or reject "
                    "logging/* requests."
                ),
                cwe="CWE-440",
            ))

        # ------------------------------------------------------------------
        # Vector 2: Probe tools after debug to see if leakage increased
        # ------------------------------------------------------------------
        if accepted_debug and probe_tools_after_debug:
            tools = (disc.get("tools") or [])[:6]
            for t in tools:
                # invalid args to provoke an error message
                bad_args = {"__minerva_log_probe": "X" * 8}
                resp = mcp_client.call(
                    target, "tools/call",
                    {"name": t.get("name"), "arguments": bad_args},
                    timeout=timeout,
                )
                body = (resp.get("response") or {})
                err = body.get("error") or {}
                err_text = (err.get("message") or "") + "\n" + str(err.get("data") or "")
                # Also check the result content text fields
                result = body.get("result") or {}
                content = result.get("content") or []
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        err_text += "\n" + str(c.get("text") or "")
                hits = _scan_for_leaks(err_text)
                if hits:
                    f = evidence.Finding(
                        attack_id=context.get("attack_id", "logging_set_level_abuse"),
                        title=f"Verbose logging exposes sensitive data via tool {t.get('name')!r}",
                        category="logging_verbose_leak",
                        severity="high", confidence="confirmed",
                        tool=t.get("name"),
                        description=(
                            "After flipping logging/setLevel to debug, calling "
                            f"tool {t.get('name')!r} with invalid arguments "
                            f"produced response/error text containing "
                            f"{len(hits)} sensitive item(s): "
                            + ", ".join(h[0] for h in hits)
                        ),
                        impact=(
                            "Attacker can trigger arbitrary errors and harvest "
                            "secrets, stack traces, internal paths, or SQL "
                            "queries from verbose log output."
                        ),
                        remediation=(
                            "Sanitise log output regardless of level. Never "
                            "include secrets in error messages, even at debug."
                        ),
                        cwe="CWE-209",
                        references=[
                            "https://cwe.mitre.org/data/definitions/209.html",
                        ],
                    )
                    f.add_evidence(evidence.ev_mcp_call(resp, note="probe after debug"))
                    f.add_evidence(evidence.ev_raw(
                        "leak hits",
                        [{"type": h[0], "snippet": h[1]} for h in hits],
                    ))
                    rb.add_finding(f)

        # ------------------------------------------------------------------
        # Vector 3: Invalid levels
        # ------------------------------------------------------------------
        if test_invalid_levels:
            for lvl in ["trace", "fatal+1", "9999", "verbose", "all", ""]:
                resp = mcp_client.call(
                    target, "logging/setLevel",
                    {"level": lvl}, timeout=timeout,
                )
                resp_body = (resp.get("response") or {})
                accepted = "error" not in resp_body and resp.get("status") in (200, None)
                if accepted and lvl not in _STD_LEVELS:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "logging_set_level_abuse"),
                        title=f"logging/setLevel accepts non-standard level {lvl!r}",
                        category="logging_set_level_validation",
                        severity="low", confidence="high",
                        parameter="level",
                        payload=lvl,
                        description=(
                            f"Server accepted level {lvl!r} which is not in "
                            f"the MCP-defined set ({_STD_LEVELS}). Suggests "
                            "missing input validation on the control surface."
                        ),
                        impact="Indicates lax validation; may enable downstream parsing bugs.",
                        remediation="Validate level against the MCP-defined enumeration.",
                        cwe="CWE-20",
                    ))
        # Reset to a safe level
        try:
            mcp_client.call(target, "logging/setLevel",
                            {"level": "warning"}, timeout=timeout)
        except Exception:
            pass

        return rb.finalize()
    finally:
        try:
            mcp.close()
        except Exception:
            pass
