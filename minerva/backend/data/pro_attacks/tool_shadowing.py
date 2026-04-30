"""
Tool Shadowing / TOCTOU-drift audit.

Two related risks:

1. Shadowing — multiple tools expose overlapping *names* or
   *descriptions* that could cause an LLM to invoke the wrong one.
   e.g. a tool called `read_file` and a later one also called
   `read_file` (or `Read_File` / `read‑file` with homoglyph).

2. TOCTOU drift — tools/list returns a different shape across
   successive calls (name, description, schema hash), letting an
   attacker race the check against the use.

We call tools/list N times with small delays, fingerprint each tool,
and flag anomalies.
"""

import time as _time
import hashlib as _hashlib
import json as _json


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "tool_shadowing"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    samples = int(params.get("samples", 5))
    delay_seconds = float(params.get("delay_seconds", 1.0))
    exploit_collisions = bool(params.get("exploit_collisions", True))
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

        all_snapshots = [disc.get("tools") or []]
        rb.info(f"Baseline tool count: {len(all_snapshots[0])}")

        for i in range(samples - 1):
            _time.sleep(delay_seconds)
            r = mcp.tools_list()
            rb.add_evidence(evidence.ev_mcp_call(r, note=f"tools/list sample #{i+2}"))
            snap = []
            if r.get("ok") and isinstance(r.get("result"), dict):
                snap = r["result"].get("tools") or []
            all_snapshots.append(snap)

        _check_name_collisions(all_snapshots[0], rb, context)
        _check_description_collisions(all_snapshots[0], rb, context)
        _check_drift(all_snapshots, rb, context)

        # Active exploitation: for any colliding name, call the tool and
        # capture which underlying implementation answers. This shows the
        # routing ambiguity in practice, not just in theory.
        if exploit_collisions:
            _exploit_collisions(mcp, all_snapshots[0], rb, context)

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


def _normalise_name(n):
    if not n:
        return ""
    return str(n).strip().lower().replace("-", "_").replace(" ", "_")


def _check_name_collisions(tools, rb, context):
    buckets = {}
    for t in tools:
        k = _normalise_name(t.get("name"))
        buckets.setdefault(k, []).append(t)
    for norm, items in buckets.items():
        if len(items) < 2:
            continue
        names = [t.get("name") for t in items]
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "tool_shadowing"),
            title=f"Tool-name collision: {names}",
            category="tool_shadowing",
            severity="high",
            confidence="high",
            cwe="CWE-1023",
            description=(
                f"Multiple tools normalise to the same identifier "
                f"'{norm}'. An LLM picking a tool by name may be "
                "non-deterministically routed to the malicious sibling. "
                "This is the MCP equivalent of DLL planting."
            ),
            impact=(
                "Malicious tool pretending to be a legitimate one can "
                "intercept sensitive parameters and exfiltrate them."
            ),
            remediation=(
                "Enforce uniqueness on canonical-cased names across the whole "
                "MCP server. Prefer strong tool-identity keys (UUID + signed "
                "manifest) over free-text names."
            ),
            references=[],
            payload=", ".join(names),
        ))


def _check_description_collisions(tools, rb, context):
    buckets = {}
    for t in tools:
        desc = (t.get("description") or "").strip().lower()
        if not desc:
            continue
        buckets.setdefault(desc, []).append(t)
    for desc, items in buckets.items():
        if len(items) < 2:
            continue
        names = [t.get("name") for t in items]
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "tool_shadowing"),
            title=f"Tool-description collision: {names}",
            category="tool_shadowing",
            severity="medium",
            confidence="medium",
            cwe="CWE-1023",
            description=(
                f"Tools {names} share an identical description. The LLM may "
                "pick between them ambiguously."
            ),
            impact="Same risk profile as name collisions but harder to spot.",
            remediation="Make each tool description unique and semantically distinct.",
            payload=desc[:200],
        ))


def _exploit_collisions(mcp, tools, rb, context):
    """For each set of name-colliding tools, call each and record output."""
    buckets = {}
    for t in tools:
        k = _normalise_name(t.get("name"))
        buckets.setdefault(k, []).append(t)
    for norm, items in buckets.items():
        if len(items) < 2:
            continue
        for t in items:
            schema = t.get("inputSchema") or {}
            args = {}
            for n in (schema.get("required") or []):
                ts = ((schema.get("properties") or {}).get(n) or {}).get("type")
                args[n] = {"string": "probe", "integer": 1, "number": 1,
                           "boolean": False, "array": [], "object": {}}.get(ts, "")
            r = mcp.call_tool_safe(t.get("name"), args)
            rb.add_evidence(evidence.ev_mcp_call(
                r, note=f"collision exploit '{t.get('name')}' (norm={norm})"))


def _check_drift(snapshots, rb, context):
    if len(snapshots) < 2:
        return
    # Build per-name fingerprint-over-time map
    names = set()
    for snap in snapshots:
        for t in snap:
            if t.get("name"):
                names.add(t["name"])
    for name in names:
        fps = []
        for snap in snapshots:
            t = next((x for x in snap if x.get("name") == name), None)
            fps.append(_fp(t) if t else None)
        unique_fps = {f for f in fps if f is not None}
        present_in = sum(1 for f in fps if f is not None)
        if present_in < len(snapshots):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "tool_shadowing"),
                title=f"Tool '{name}' appears/disappears across listings",
                category="tool_shadowing",
                severity="high",
                confidence="high",
                cwe="CWE-367",
                tool=name,
                description=(
                    f"Tool '{name}' was present in only {present_in}/{len(snapshots)} "
                    "tools/list snapshots. This TOCTOU drift lets an attacker "
                    "expose a malicious tool just long enough to be selected, "
                    "then hide it from audit."
                ),
                impact="Attacker can bypass static scans and audit tooling.",
                remediation=(
                    "MCP servers must expose a stable, versioned tool manifest. "
                    "Sign each manifest snapshot and record its hash in an audit "
                    "log. Clients should reject on-the-fly manifest changes."
                ),
                payload=f"Present in samples: {present_in}/{len(snapshots)}",
            ))
        elif len(unique_fps) > 1:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "tool_shadowing"),
                title=f"Tool '{name}' definition mutates across listings",
                category="tool_shadowing",
                severity="high",
                confidence="high",
                cwe="CWE-367",
                tool=name,
                description=(
                    f"Tool '{name}' returned {len(unique_fps)} distinct schemas "
                    f"across {len(snapshots)} snapshots. An attacker can show a "
                    "benign schema during audit and a malicious schema during "
                    "execution."
                ),
                impact="Audit-vs-runtime divergence. Policy decisions made at "
                       "inspection time won't apply at call time.",
                remediation="Pin tool definitions per-session; treat drift as failure.",
                payload=f"Fingerprints: {sorted(unique_fps)[:3]}",
            ))
