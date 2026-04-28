"""
Configuration Drift — samples the server's reported capabilities /
tool-list / resource-list multiple times over a short window and flags
any drift between the snapshots.
"""

import time as _time


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "config_drift"), target)
    timeout = int(params.get("timeout", 15))
    samples = int(params.get("samples", 4))
    delay = float(params.get("delay_seconds", 0.5))

    snapshots = []
    for i in range(samples):
        client = mcp_client.MCPClient.from_target(target, timeout=timeout)
        try:
            disc = client.discover()
            snapshots.append({
                "server_info": disc.get("server_info"),
                "protocol_version": disc.get("protocol_version"),
                "capabilities": disc.get("capabilities"),
                "tool_count": len(disc.get("tools") or []),
                "tool_names": sorted(t.get("name")
                                     for t in (disc.get("tools") or [])
                                     if t.get("name")),
                "resource_uris": sorted(r.get("uri")
                                        for r in (disc.get("resources") or [])
                                        if r.get("uri")),
            })
        finally:
            client.close()
        if i < samples - 1:
            _time.sleep(delay)

    rb.add_evidence(evidence.ev_raw("snapshots", snapshots))
    baseline = snapshots[0]
    for i, s in enumerate(snapshots[1:], start=2):
        diffs = {k: (baseline[k], s[k]) for k in baseline
                 if baseline[k] != s[k]}
        if not diffs: continue
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "config_drift"),
            title=f"Server config drift detected at sample #{i}",
            category="configuration_drift",
            severity="medium", confidence="confirmed", cwe="CWE-16",
            description=(
                f"Differences vs baseline sample: {list(diffs.keys())}. "
                "A server that mutates its exposed capabilities over short "
                "intervals is either rolling a bad config, load-balancing "
                "inconsistent backends, or being actively tampered with."
            ),
            impact=(
                "Security audits capture one view; runtime behaviour is "
                "another. Policy decisions based on a static snapshot are "
                "unreliable."
            ),
            remediation=(
                "Pin server config per-deployment; run identical images "
                "across all backend replicas; monitor tools/list output "
                "for unexpected changes."
            ),
            payload=f"diff_keys={list(diffs.keys())}",
        ))
        return rb.finalize()
    return rb.finalize()
