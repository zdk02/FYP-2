"""
Resource Exhaustion / DoS posture (Pro).

Non-destructive — measures *acceptance* of dangerous shapes without
actually tipping the target over.

Tests
-----
1. Baseline latency (3 samples, median).
2. Oversized argument acceptance + latency-degradation curve at 1×, 4×,
   16× the configured size.
3. Deeply-nested JSON.
4. Concurrency burst with rate-limit-header inspection (429, X-RateLimit*).
5. ReDoS catastrophic-backtracking probe — feed `aaaaaa...aaaaaaa!`
   shaped strings (vulnerable regexes blow up exponentially).
6. Response-size amplification — small request, large response (1KB →
   MBs), useful for billing/bandwidth DoS.
"""

import time as _time
import json as _json
import concurrent.futures as _cf


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "resource_exhaustion"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    concurrency_burst = int(params.get("concurrency_burst", 12))
    big_string_kb = int(params.get("big_string_kb", 64))
    deep_nesting = int(params.get("deep_nesting", 200))
    test_redos = bool(params.get("test_redos", True))
    test_amplification = bool(params.get("test_amplification", True))
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
            init_resp = (disc.get("raw") or {}).get("initialize") or {}
            rb.error(f"MCP initialize failed: {disc.get('errors')}")
            rb.add_evidence(evidence.ev_mcp_call(init_resp, note="failed initialize"))
            return rb.finalize(success=False)
        tools = disc.get("tools") or []

        # Pick a probe tool with a string param
        probe = next(
            (t for t in tools
             if any(isinstance(s, dict) and s.get("type") == "string"
                    for s in (t.get("inputSchema") or {}).get("properties", {}).values())),
            None
        )
        if not probe:
            rb.warn("No string-arg tool to probe with.")
            return rb.finalize(success=True)
        tname = probe.get("name")
        schema = probe.get("inputSchema") or {}
        str_param = next(n for n, s in (schema.get("properties") or {}).items()
                         if isinstance(s, dict) and s.get("type") == "string")
        rb.info(f"Probe: {tname}/{str_param}")

        # --- Baseline ---
        baseline_times = []
        for _ in range(3):
            args = helpers.fill_defaults(schema); args[str_param] = "x"
            t0 = _time.time()
            mcp.call_tool_safe(tname, args)
            baseline_times.append(_time.time() - t0)
        baseline_times.sort()
        baseline = baseline_times[1]
        rb.info(f"Baseline median latency: {baseline:.3f}s")

        # --- 1. Oversized argument + degradation curve ---
        for mult in (1, 4, 16):
            sz = big_string_kb * mult
            big = "A" * (sz * 1024)
            args = helpers.fill_defaults(schema); args[str_param] = big
            t0 = _time.time()
            r = mcp.call_tool_safe(tname, args)
            dt = _time.time() - t0
            rb.add_evidence(evidence.ev_mcp_call(
                r, note=f"oversize {sz}KB latency {dt:.2f}s"))
            if r.get("ok") and not r.get("is_error"):
                slowdown = (dt / baseline) if baseline > 0 else 0
                if mult == 1:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "resource_exhaustion"),
                        title=f"{sz}KB argument accepted on '{tname}'",
                        category="resource_exhaustion",
                        severity="medium",
                        confidence="high" if slowdown > 5 else "medium",
                        cwe="CWE-400",
                        tool=tname, parameter=str_param,
                        payload=f"{sz}KB of 'A' (latency {dt:.2f}s, "
                                f"baseline {baseline:.3f}s, {slowdown:.0f}x)",
                        description=(
                            f"Server accepted a {sz}KB argument. Latency was "
                            f"{slowdown:.1f}× baseline."
                        ),
                        impact="At scale, cheap DoS primitive. Larger args may "
                               "trigger ReDoS / parser bugs.",
                        remediation="Enforce per-param size caps (e.g. 64KB "
                                    "string, 256KB total request).",
                    ))

        # --- 2. Deeply-nested JSON (parser DoS) ---
        nested_str = _json.dumps(_nested_array(deep_nesting))[:256 * 1024]
        args = helpers.fill_defaults(schema); args[str_param] = nested_str
        t0 = _time.time()
        r = mcp.call_tool_safe(tname, args)
        dt = _time.time() - t0
        rb.add_evidence(evidence.ev_mcp_call(
            r, note=f"deep-nest {deep_nesting} latency {dt:.2f}s"))
        if r.get("ok") and not r.get("is_error"):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "resource_exhaustion"),
                title=f"Deeply-nested JSON accepted (depth {deep_nesting})",
                category="resource_exhaustion",
                severity="low" if dt < 5 else "medium",
                confidence="confirmed", cwe="CWE-674",
                tool=tname, parameter=str_param,
                payload=f"depth={deep_nesting}",
                description=(f"Server accepted depth-{deep_nesting} JSON in "
                             f"{dt:.2f}s. Without max-depth, attacker may "
                             "stack-overflow the parser."),
                remediation="Enforce JSON max-depth ≤ 64 at parse time.",
            ))

        # --- 3. Concurrency burst + rate-limit headers ---
        def _hit(_i):
            t = _time.time()
            mc = mcp_client.MCPClient.from_target(
                target, timeout=timeout,
                protocol_version=protocol_version,
                force_transport=transport_override,
            )
            try:
                r = mc.initialize()
                return r.get("ok"), r.get("status"), r.get("headers") or {}, _time.time() - t
            finally:
                mc.close()
        with _cf.ThreadPoolExecutor(max_workers=concurrency_burst) as pool:
            results = list(pool.map(_hit, range(concurrency_burst)))
        oks = sum(1 for ok, *_ in results if ok)
        rl_hits = [hdrs for _ok, _s, hdrs, _dt in results
                    if any(k.lower().startswith("x-ratelimit")
                            or k.lower() == "retry-after"
                            for k in (hdrs or {}).keys())]
        rb.info(f"Concurrent inits: {oks}/{concurrency_burst} ok, "
                f"{len(rl_hits)} responses had rate-limit headers")
        if oks == concurrency_burst and not rl_hits:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "resource_exhaustion"),
                title=f"No rate-limit on initialize ({concurrency_burst} concurrent ok)",
                category="resource_exhaustion",
                severity="medium", confidence="high", cwe="CWE-770",
                description=(f"All {concurrency_burst} concurrent MCP "
                             "initialize handshakes succeeded with no "
                             "X-RateLimit-* / Retry-After headers."),
                impact="Cheap DoS. Easy to exhaust DB pool / LLM quota / mem.",
                remediation=("Apply per-IP, per-token, per-tool concurrency "
                             "limits via a token bucket. Surface "
                             "X-RateLimit-* headers."),
            ))

        # --- 4. ReDoS catastrophic-backtracking probe ---
        if test_redos:
            evil_strings = [
                "a" * 30 + "!",
                ("a" * 50) + "X",
                "(" * 50 + "a" * 50,
                "x" * 1000 + "@",
            ]
            redos_dt = []
            for s in evil_strings:
                args = helpers.fill_defaults(schema); args[str_param] = s
                t0 = _time.time()
                mcp.call_tool_safe(tname, args)
                redos_dt.append(_time.time() - t0)
            mx = max(redos_dt)
            if mx > baseline * 30 and mx > 3:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "resource_exhaustion"),
                    title=f"Possible ReDoS: response time spiked to {mx:.2f}s",
                    category="resource_exhaustion",
                    severity="medium", confidence="medium", cwe="CWE-1333",
                    tool=tname, parameter=str_param,
                    description=(f"Latency spike on backtracking-bait input "
                                 f"({mx:.2f}s vs {baseline:.3f}s baseline, "
                                 f"{mx/baseline:.0f}×). Server-side regex "
                                 "may be vulnerable."),
                    remediation=("Audit regexes; replace catastrophic patterns "
                                 "with possessive quantifiers / RE2."),
                    payload=f"max_dt={mx:.2f}s baseline={baseline:.3f}s",
                ))

        # --- 5. Response-size amplification ---
        if test_amplification:
            args = helpers.fill_defaults(schema); args[str_param] = "*" * 100
            r = mcp.call_tool_safe(tname, args)
            req_size = len(_json.dumps(args))
            resp_size = len(r.get("text_output") or "")
            if resp_size > 1024 * 1024 and resp_size > req_size * 1000:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "resource_exhaustion"),
                    title=f"Response-size amplification on '{tname}'",
                    category="resource_exhaustion",
                    severity="low", confidence="confirmed", cwe="CWE-405",
                    tool=tname,
                    description=(f"Request {req_size}B → response {resp_size}B "
                                 f"({resp_size//req_size}×). Attackers can "
                                 "exhaust client bandwidth."),
                    remediation=("Cap response size; paginate large results."),
                    payload=f"{req_size}B → {resp_size}B",
                ))
        return rb.finalize()
    finally:
        mcp.close()


def _nested_array(depth):
    node = "x"
    for _ in range(depth):
        node = [node]
    return node
