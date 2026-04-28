"""
Vulnerable Client — server-side audit of the CLIENT's advertised
identity (via the initialize clientInfo echoed in server responses,
custom headers, or the server's own leaked warnings about outdated
clients).

Light-weight complement to the MCP Client Vulnerability Scanner plugin
— this runs inline against any target and flags obvious signals.
"""

import re as _re


_DANGEROUS_CLIENT_PATTERNS = [
    (r"(?i)outdated\s+client", "server warns about outdated clients"),
    (r"(?i)unsupported\s+(?:client|protocol\s+version)",
     "server rejects some clients"),
    (r"(?i)please\s+upgrade\b", "upgrade prompt"),
    (r"(?i)security\s+(?:advisory|alert)", "security advisory text"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "vuln_client"), target)
    timeout = int(params.get("timeout", 15))

    # Try an initialize with a deliberately-old protocol version
    t = dict(target)
    client = mcp_client.MCPClient.from_target(t, timeout=timeout)
    try:
        # Old protocol version probe
        old = client.initialize(protocol_version="2023-01-01")
        rb.add_evidence(evidence.ev_mcp_call(old, note="init old protocol"))
        if old.get("ok"):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "vuln_client"),
                title="Server accepts obsolete MCP protocol versions",
                category="vulnerable_client", severity="medium",
                confidence="high", cwe="CWE-1104",
                description=(
                    "A handshake announcing protocol version '2023-01-01' "
                    "(which did not exist) was accepted. The server does "
                    "not pin clients to a supported version range."
                ),
                impact=(
                    "Clients speaking deprecated protocol variants with "
                    "known flaws remain silently supported."
                ),
                remediation=(
                    "Reject handshakes whose protocolVersion is older than "
                    "the minimum supported. Log for monitoring."
                ),
                payload="protocolVersion=2023-01-01",
            ))
    finally:
        client.close()

    # Scan server response text for client-related warnings
    client = mcp_client.MCPClient.from_target(target, timeout=timeout)
    try:
        disc = client.discover()
        blob = (str(disc.get("server_info") or "") + " "
                + " ".join(str(t) for t in (disc.get("tools") or [])))
        for pat, label in _DANGEROUS_CLIENT_PATTERNS:
            m = _re.search(pat, blob)
            if m:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "vuln_client"),
                    title=f"Server advertises client-version sensitivity ({label})",
                    category="vulnerable_client", severity="low",
                    confidence="medium", cwe="CWE-1104",
                    description=(
                        f"Server metadata contains '{m.group(0)}' — the "
                        "deployment exposes version sensitivity to attackers."
                    ),
                    remediation=(
                        "Do not expose version-enforcement messages to "
                        "unauthenticated clients."
                    ),
                    payload=m.group(0),
                ))
                break
    finally:
        client.close()
    return rb.finalize()
