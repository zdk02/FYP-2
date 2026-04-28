"""
Information Disclosure audit for MCP servers.

Looks for things a mature server should NOT leak:
  - Stack traces / framework versions in error responses
  - Server/Powered-By headers advertising versions
  - Debug endpoints (/debug, /metrics, /trace, /.env, /docs)
  - Secrets leaking in tool responses (API keys, cloud creds,
    private keys, database URLs)
  - Verbose JSON-RPC error messages (file paths, library internals)

Complements MCP MITM Data-in-Transit Posture (Pro) without overlap —
this one focuses on leakage *inside* MCP responses, not on the channel.
"""

import re as _re


_STACK_MARKERS = (
    "traceback (most recent call last)",
    "at java.", "at sun.", "org.springframework",
    "at node_modules", "\n    at ", "node internal/",
    "nullpointerexception", "python:", ".py\", line",
    "error in ./", "/usr/lib/python", "/var/www/",
)

_DEBUG_PATHS = (
    "/debug", "/debug/pprof", "/metrics", "/actuator",
    "/actuator/env", "/actuator/heapdump", "/.env", "/.git/config",
    "/swagger.json", "/openapi.json", "/graphql", "/trace",
    "/console", "/logs", "/status",
)

_SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9]{20,}",                    "OpenAI-style API key"),
    (r"sk-ant-[A-Za-z0-9_-]{20,}",              "Anthropic API key"),
    (r"xoxb-[A-Za-z0-9-]+",                     "Slack bot token"),
    (r"ghp_[A-Za-z0-9]{20,}",                   "GitHub PAT"),
    (r"AKIA[0-9A-Z]{16}",                       "AWS access key"),
    (r"AIza[0-9A-Za-z_-]{35}",                  "Google API key"),
    (r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----", "private key"),
    (r"postgres(?:ql)?://[^:]+:[^@]+@",         "Postgres URL w/ password"),
    (r"mysql://[^:]+:[^@]+@",                    "MySQL URL w/ password"),
    (r"mongodb(?:\+srv)?://[^:]+:[^@]+@",       "MongoDB URL w/ password"),
    (r"(?i)(?:password|passwd|secret|token|api[_-]?key)"
     r"\s*[:=]\s*['\"][^'\"]{8,}['\"]",          "credential-like assignment"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "information_disclosure"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    probe_debug_paths = bool(params.get("probe_debug_paths", True))
    probe_tool_responses = bool(params.get("probe_tool_responses", True))

    # 1. Debug paths (unauthenticated HTTP probes)
    base = target.get("base_url") \
        or f"{target.get('protocol','http')}://{target.get('host','localhost')}:{target.get('port',80)}"
    if probe_debug_paths:
        for path in _DEBUG_PATHS:
            url = base.rstrip("/") + path
            try:
                r = requests.get(url, timeout=timeout, allow_redirects=False,
                                 verify=False)
            except Exception:
                continue
            if r.status_code < 400 and len(r.text or "") > 0:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id",
                                           "information_disclosure"),
                    title=f"Debug/management path exposed: {path}",
                    category="information_disclosure",
                    severity="high",
                    confidence="confirmed",
                    cwe="CWE-200",
                    description=(
                        f"GET {url} returned HTTP {r.status_code} with a "
                        f"{len(r.text)}-byte body. Debug or management "
                        "endpoints should never be world-reachable in "
                        "production."
                    ),
                    remediation=(
                        "Bind management endpoints to localhost or a private "
                        "VPC, or require a dedicated auth header."
                    ),
                    payload=url,
                    evidence=[evidence.ev_http(
                        {"method": "GET", "url": url},
                        {"status": r.status_code,
                         "headers": dict(r.headers),
                         "body": r.text[:2000]})],
                ))

    # 2. Banner / version headers
    try:
        r = requests.get(base.rstrip("/") + "/mcp",
                         timeout=timeout, verify=False)
        headers = {k.lower(): v for k, v in r.headers.items()}
        for h in ("server", "x-powered-by", "x-aspnet-version",
                  "x-runtime"):
            if h in headers and any(c.isdigit() for c in headers[h]):
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id",
                                           "information_disclosure"),
                    title=f"Version disclosed in '{h}' header",
                    category="information_disclosure",
                    severity="low",
                    confidence="confirmed",
                    cwe="CWE-200",
                    description=(
                        f"Response header {h}: {headers[h]}. Advertised "
                        "versions help attackers target known CVEs."
                    ),
                    remediation="Strip / rewrite server version headers at "
                                "the reverse proxy.",
                    payload=f"{h}: {headers[h]}",
                ))
    except Exception:
        pass

    # 3. Verbose errors + secret leakage via MCP JSON-RPC
    mcp = mcp_client.MCPClient.from_target(target, timeout=timeout)
    try:
        init = mcp.initialize()
        rb.add_evidence(evidence.ev_mcp_call(init, note="initialize"))
        if not init.get("ok"):
            rb.warn("Could not initialize for deep probes; skipping.")
            return rb.finalize(success=True)

        # Trigger a syntactically invalid call
        bad = mcp.transport.send("tools/call", {"name": "___nope___",
                                                 "arguments": {}})
        rb.add_evidence(evidence.ev_mcp_call(bad, note="invalid tool call"))
        err = bad.get("error") or {}
        err_msg = str(err.get("message") or err.get("data") or bad.get("response"))
        if _looks_like_stack(err_msg):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id",
                                       "information_disclosure"),
                title="Stack trace / internal path leaked in MCP error",
                category="information_disclosure",
                severity="medium",
                confidence="confirmed",
                cwe="CWE-209",
                description=(
                    "A deliberately invalid tool invocation returned an "
                    "error message containing stack-trace-like internals. "
                    f"Excerpt: {err_msg[:200]!r}"
                ),
                remediation=(
                    "Wrap JSON-RPC handlers in a sanitising layer: return a "
                    "generic 'invalid request' message, log the full trace "
                    "server-side only."
                ),
                payload="tools/call name='___nope___'",
                evidence=[evidence.ev_mcp_call(bad)],
            ))

        # Tool-response secret scan
        if probe_tool_responses:
            tl = mcp.tools_list()
            if tl.get("ok"):
                tools = (tl.get("result") or {}).get("tools") or []
                for t in tools[:12]:
                    name = t.get("name")
                    if not name:
                        continue
                    args = _fill_defaults(t.get("inputSchema") or {})
                    r = mcp.call_tool_safe(name, args)
                    text = r.get("text_output") or ""
                    for pat, label in _SECRET_PATTERNS:
                        m = _re.search(pat, text)
                        if m:
                            rb.add_finding(evidence.Finding(
                                attack_id=context.get("attack_id",
                                                       "information_disclosure"),
                                title=f"Secret in '{name}' response: {label}",
                                category="information_disclosure",
                                severity="high",
                                confidence="high",
                                cwe="CWE-532",
                                tool=name,
                                payload=m.group(0)[:80],
                                description=(
                                    f"Tool '{name}' returned data matching a "
                                    f"{label} pattern."
                                ),
                                remediation=(
                                    "Never return raw credentials. Replace "
                                    "with opaque reference IDs and resolve "
                                    "server-side."
                                ),
                                evidence=[evidence.ev_mcp_call(r)],
                            ))
                            break
        return rb.finalize()
    finally:
        mcp.close()


def _looks_like_stack(msg):
    m = msg.lower()
    return any(k in m for k in _STACK_MARKERS)


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "a", "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out
