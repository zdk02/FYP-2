"""
MCP Tool Rebinding — focused TOCTOU RACE with precise timing.

Hammers tools/list while calling a target tool in another thread;
reports the time delta between the approval-time schema and the
execution-time schema if they diverge.
"""

import threading as _threading
import time as _time


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "rebinding_race"), target)
    timeout = int(params.get("timeout", 20))
    race_seconds = int(params.get("race_seconds", 4))

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
        tools = helpers.tools_with_string_param(disc.get("tools") or [])
        if not tools:
            rb.warn("No string-arg tools."); return rb.finalize(success=True)
        probe = tools[0]
        pname = probe.get("name")

        fps = []  # (t, fingerprint)
        stop = False
        def hammer():
            client = mcp_client.MCPClient.from_target(target, timeout=timeout)
            client.initialize()
            deadline = _time.time() + race_seconds
            while not stop and _time.time() < deadline:
                r = client.tools_list()
                if r.get("ok"):
                    for t in (r.get("result") or {}).get("tools") or []:
                        if t.get("name") == pname:
                            fps.append((_time.time(), helpers.tool_fingerprint(t)))
                            break
                _time.sleep(0.05)
            client.close()

        t = _threading.Thread(target=hammer, daemon=True); t.start()

        # In parallel, keep exercising the tool
        schema = probe.get("inputSchema") or {}
        for _ in range(max(1, race_seconds * 2)):
            args = helpers.fill_defaults(schema)
            args[helpers.string_params(schema)[0]] = "race"
            r = mcp.call_tool_safe(pname, args)
            _time.sleep(0.2)
        stop = True; t.join(timeout=2)

        uniques = {fp for _, fp in fps}
        rb.info(f"Observed {len(fps)} snapshots, {len(uniques)} distinct fingerprints")
        if len(uniques) > 1:
            times = [ts for ts, _ in fps]
            span = (max(times) - min(times)) if times else 0
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "rebinding_race"),
                title=f"Tool '{pname}' definition mutates during concurrent use",
                category="tool_rebinding", severity="high",
                confidence="confirmed", cwe="CWE-367", tool=pname,
                description=(
                    f"Observed {len(uniques)} distinct tool-schema "
                    f"fingerprints within a {span:.1f}s race window. This is "
                    "the MCP analogue of DNS rebinding — audit-time schema "
                    "does not match execution-time schema."
                ),
                impact=(
                    "Security reviews of the tool manifest are meaningless; "
                    "the runtime semantics change under attacker control."
                ),
                remediation=(
                    "Pin tool manifests per-session at first tools/list. "
                    "Reject any tool that returns different schemas across "
                    "a single session."
                ),
                payload=f"race_seconds={race_seconds}",
            ))
        return rb.finalize()
    finally:
        mcp.close()
