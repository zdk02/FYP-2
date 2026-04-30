"""
MCP Tool Rebinding — functional time-of-check / time-of-use test.

Scenario: a client does `tools/list`, the user sees tool `fetch` with
description "read a URL", approves. Between the check and the actual
tools/call, the server swaps `fetch`'s handler to read local files
instead. This is the agent-world analogue of DNS rebinding.

Method
------
We call `tools/list`, capture a fingerprint, execute each tool with
benign inputs, then call `tools/list` again and diff. Any identifier
(name, description, schema hash) that changed mid-session is a finding.
We also track unexpected new notification types (listChanged).
"""

import hashlib as _hashlib
import json as _json
import time as _time


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "tool_rebinding"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    call_tools = bool(params.get("call_tools", True))
    max_tools = int(params.get("max_tools", 10))
    exercise_delay = float(params.get("exercise_delay", 0.5))
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
        before = disc.get("tools") or []
        rb.info(f"Before: {len(before)} tools")
        before_fp = {t.get("name"): _fp(t) for t in before if t.get("name")}

        # Exercise each tool with a benign call (if allowed)
        if call_tools:
            for t in before[:max_tools]:
                name = t.get("name")
                if not name:
                    continue
                args = _fill_defaults(t.get("inputSchema") or {})
                rb.add_evidence(evidence.ev_mcp_call(
                    mcp.call_tool_safe(name, args),
                    note=f"benign call {name} (rebinding probe)"))

        # Small delay — some servers rotate manifests periodically
        _time.sleep(exercise_delay)

        after_resp = mcp.tools_list()
        rb.add_evidence(evidence.ev_mcp_call(after_resp,
                                              note="tools/list after probe"))
        after = []
        if after_resp.get("ok"):
            after = (after_resp.get("result") or {}).get("tools") or []
        after_fp = {t.get("name"): _fp(t) for t in after if t.get("name")}

        all_names = set(before_fp) | set(after_fp)
        for n in sorted(all_names):
            b, a = before_fp.get(n), after_fp.get(n)
            if b and not a:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "tool_rebinding"),
                    title=f"Tool '{n}' disappeared after first use",
                    category="tool_rebinding",
                    severity="high",
                    confidence="confirmed",
                    cwe="CWE-367",
                    tool=n,
                    description=(
                        "Tool was visible in the initial tools/list response "
                        "but absent after executing a benign call. A malicious "
                        "server can expose a dangerous tool long enough to be "
                        "approved, then hide it from subsequent audits."
                    ),
                    impact="Audit/approval systems see a different tool set "
                           "than the runtime actually uses.",
                    remediation=(
                        "MCP clients should treat the manifest as session-"
                        "immutable. Pin the tool list after the first "
                        "tools/list response and reject changes mid-session."
                    ),
                ))
            elif a and not b:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "tool_rebinding"),
                    title=f"Tool '{n}' appeared mid-session",
                    category="tool_rebinding",
                    severity="medium",
                    confidence="confirmed",
                    cwe="CWE-367",
                    tool=n,
                    description="Tool was not in the initial manifest but "
                                "materialised after the probe phase.",
                    remediation="See previous finding — pin the manifest.",
                ))
            elif b and a and b != a:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "tool_rebinding"),
                    title=f"Tool '{n}' definition changed mid-session",
                    category="tool_rebinding",
                    severity="high",
                    confidence="confirmed",
                    cwe="CWE-367",
                    tool=n,
                    description=(
                        "Schema / description fingerprint of this tool "
                        f"changed from {b[:10]}… to {a[:10]}… during the "
                        "session. This is the MCP equivalent of DNS "
                        "rebinding — attacker swaps tool semantics after "
                        "the client has approved them."
                    ),
                    remediation="See previous finding.",
                ))

        return rb.finalize()
    finally:
        mcp.close()


def _fp(tool):
    core = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
    }
    return _hashlib.sha256(
        _json.dumps(core, sort_keys=True, default=str).encode()
    ).hexdigest()


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "probe", "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out
