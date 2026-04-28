"""
Package Name Squatting — checks the server's self-reported name /
version against a small database of known-good MCP packages and flags
typosquat candidates.

Offline-only (no package registry queries). Operates on the server info
returned by MCP initialize.
"""

import difflib as _difflib


# Known-good MCP server / client packages the community trusts.
_KNOWN = [
    "anthropic", "claude", "claude-code", "mcp-server-filesystem",
    "mcp-server-github", "mcp-server-postgres", "mcp-server-gitlab",
    "mcp-server-slack", "mcp-server-sqlite", "mcp-server-sentry",
    "mcp-server-puppeteer", "mcp-server-brave-search",
    "mcp-server-google-drive", "mcp-inspector", "mcp-remote",
    "cursor", "windsurf", "zed", "roo-code", "junie",
    "continue", "cline",
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "squat"), target)
    timeout = int(params.get("timeout", 15))
    min_ratio = float(params.get("min_similarity", 0.75))

    mcp = mcp_client.MCPClient.from_target(target, timeout=timeout)
    try:
        init = mcp.initialize()
        rb.add_evidence(evidence.ev_mcp_call(init, note="initialize"))
        if not init.get("ok"):
            rb.error("MCP initialize failed.")
            return rb.finalize(success=False)
        info = (init.get("result") or {}).get("serverInfo") or {}
        name = (info.get("name") or "").lower().strip()
        if not name:
            rb.warn("Server did not return a serverInfo.name.")
            return rb.finalize(success=True)
        if name in _KNOWN:
            rb.info(f"Server identifies as a known package: '{name}'.")
            return rb.finalize(success=True)

        # Find near-matches
        suspects = []
        for k in _KNOWN:
            ratio = _difflib.SequenceMatcher(None, name, k).ratio()
            if ratio >= min_ratio:
                suspects.append((k, ratio))
        suspects.sort(key=lambda x: -x[1])

        if suspects:
            top = suspects[0]
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "squat"),
                title=f"Possible package-name squatting: '{name}' ~ '{top[0]}'",
                category="package_squatting",
                severity="medium", confidence="high",
                cwe="CWE-1357",
                description=(
                    f"Server identifies as '{name}' — {top[1]:.0%} similar "
                    f"to the known package '{top[0]}'. Typosquatting is a "
                    "common supply-chain attack on MCP ecosystems."
                ),
                impact=(
                    "Users may trust this server believing it is the "
                    "legitimate upstream. Supply-chain compromise."
                ),
                remediation=(
                    "Verify package identity via cryptographic signatures "
                    "or registry lookup; reject close-but-not-identical "
                    "names at the client level."
                ),
                payload=f"advertised='{name}', near='{top[0]}'",
                evidence=[evidence.ev_raw("top suspects", suspects[:5])],
            ))
        return rb.finalize()
    finally:
        mcp.close()
