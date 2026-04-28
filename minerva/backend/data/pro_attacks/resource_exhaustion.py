"""
Resource Exhaustion / DoS posture audit for MCP servers.

Pentester goals:
  - Does the server accept arbitrarily large tool arguments?
  - Does it honour per-call timeouts?
  - Is there any rate-limit on tools/call (or does N fast calls all succeed)?
  - Are deeply nested JSON inputs accepted (stack-depth DoS)?
  - Are "large-fanout" tools (search, list, scan) unbounded?

This is **non-destructive** — we use short sleeps and modest sizes so we
don't actually DoS the target. The goal is to observe acceptance of
dangerous shapes, not to tip the server over.
"""

import time as _time
import json as _json


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "resource_exhaustion"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    concurrency_burst = int(params.get("concurrency_burst", 12))
    big_string_kb = int(params.get("big_string_kb", 64))
    deep_nesting = int(params.get("deep_nesting", 200))

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
        if not tools:
            rb.warn("No tools exposed.")
            return rb.finalize(success=True)
        # Pick one tool with a string arg as the probe surface
        probe = None
        probe_param = None
        for t in tools:
            schema = t.get("inputSchema") or {}
            for n, s in (schema.get("properties") or {}).items():
                if isinstance(s, dict) and s.get("type") == "string":
                    probe = t; probe_param = n; break
            if probe:
                break
        if not probe:
            rb.warn("No string-arg tool to probe with.")
            return rb.finalize(success=True)
        tname = probe.get("name")
        rb.info(f"Probe tool: {tname}[{probe_param}]")

        # --- 1. Large string argument ------------------------------------
        big = "A" * (big_string_kb * 1024)
        args = _fill_defaults(probe.get("inputSchema") or {})
        args[probe_param] = big
        t0 = _time.time()
        r = mcp.call_tool_safe(tname, args)
        dt = _time.time() - t0
        rb.add_evidence(evidence.ev_mcp_call(
            r, note=f"large-string probe ({big_string_kb}KB)"))
        if r.get("ok") and not r.get("is_error"):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "resource_exhaustion"),
                title=f"{big_string_kb}KB argument accepted on '{tname}'",
                category="resource_exhaustion",
                severity="medium",
                confidence="high",
                cwe="CWE-400",
                tool=tname, parameter=probe_param,
                payload=f"{big_string_kb}KB of 'A'",
                description=(
                    f"The server accepted a {big_string_kb}KB argument "
                    f"({dt:.2f}s latency). No upper-bound enforcement means "
                    "an attacker can waste CPU/memory on every request."
                ),
                impact=(
                    "At scale, this becomes a cheap denial-of-service primitive. "
                    "Larger arguments may also trigger ReDoS / slow-parse bugs."
                ),
                remediation=(
                    "Enforce per-parameter size limits at the JSON-RPC layer "
                    "(e.g. 64KB per string, 256KB per request total)."
                ),
                references=["https://cwe.mitre.org/data/definitions/400.html"],
            ))

        # --- 2. Deeply-nested JSON (stack-depth / parser DoS) ------------
        nested = _nested_array(deep_nesting)
        # craft a fake request body purely for size; send it as the same param
        payload_str = _json.dumps(nested)[:256 * 1024]
        args2 = _fill_defaults(probe.get("inputSchema") or {})
        args2[probe_param] = payload_str
        r2 = mcp.call_tool_safe(tname, args2)
        rb.add_evidence(evidence.ev_mcp_call(
            r2, note=f"deep-nesting probe (depth={deep_nesting})"))
        if r2.get("ok") and not r2.get("is_error"):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "resource_exhaustion"),
                title=f"Deep-nested JSON payload accepted (depth {deep_nesting})",
                category="resource_exhaustion",
                severity="low",
                confidence="medium",
                cwe="CWE-674",
                tool=tname, parameter=probe_param,
                payload=f"nested array depth={deep_nesting}",
                description=(
                    "Server accepted deeply-nested JSON. Without a JSON "
                    "max-depth guard, an attacker can stack-overflow the "
                    "parser or waste cycles on traversal."
                ),
                remediation=(
                    "Configure the JSON parser with a max depth "
                    "(commonly 32-64) and reject exceeding payloads early."
                ),
                references=["https://cwe.mitre.org/data/definitions/674.html"],
            ))

        # --- 3. Concurrency burst — measure rate-limit ------------------
        burst_args = _fill_defaults(probe.get("inputSchema") or {})
        burst_args[probe_param] = "burst"
        import concurrent.futures as _cf
        def _hit(i):
            t = _time.time()
            r = mcp_client.MCPClient.from_target(target,
                                                  timeout=timeout).initialize()
            return r.get("ok"), _time.time() - t
        with _cf.ThreadPoolExecutor(max_workers=concurrency_burst) as pool:
            hits = list(pool.map(_hit, range(concurrency_burst)))
        oks = sum(1 for ok, _ in hits if ok)
        rb.info(f"concurrent initializes: {oks}/{concurrency_burst} succeeded")
        if oks == concurrency_burst:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "resource_exhaustion"),
                title=f"No rate-limit on initialize ({concurrency_burst} "
                      "simultaneous accepted)",
                category="resource_exhaustion",
                severity="medium",
                confidence="high",
                cwe="CWE-770",
                description=(
                    f"Server accepted {concurrency_burst} concurrent "
                    "MCP initialize handshakes without throttling. "
                    "An attacker can easily overwhelm session-bound "
                    "resources (CPU, memory, DB connections)."
                ),
                impact="Service degradation / downtime at low attacker cost.",
                remediation=(
                    "Apply per-IP, per-token, and per-tool concurrency limits. "
                    "Use a token bucket or leaky-bucket algorithm. "
                    "Consider an API gateway (Cloudflare, Kong, Envoy)."
                ),
                references=["https://cwe.mitre.org/data/definitions/770.html"],
            ))

        return rb.finalize()
    finally:
        mcp.close()


def _nested_array(depth):
    node = "x"
    for _ in range(depth):
        node = [node]
    return node


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "a", "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out
