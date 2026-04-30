"""
Information Disclosure (Pro) — discovered secrets are *validated*.

Pattern-matching alone (regex hits in tool output) is too noisy to put
in a pentest report. This attack scans the MCP surface for secrets,
then VALIDATES each candidate against the issuer's identity endpoint:

    AWS keys     → STS GetCallerIdentity (read-only, no IAM perm needed)
    GitHub PATs  → GET /user
    Slack tokens → auth.test
    OpenAI keys  → /v1/models
    Anthropic    → /v1/models
    Google API   → tokeninfo
    JWTs         → header analysis (alg=none, kid SQLi, weak HMAC)

Findings are graded:
    valid=True  → confidence=confirmed, severity=critical
    valid=False → confidence=high (it's still a fixture leak; lower impact)
    valid=None  → confidence=medium (could not be tested)

The attack also continues to flag stack-trace leaks, debug paths, and
verbose JSON-RPC errors (those don't need validation).
"""

import re as _re


_STACK_MARKERS = (
    "traceback (most recent call last)",
    "at java.", "at sun.", "org.springframework",
    "at node_modules", "\n    at ", "node internal/",
    "nullpointerexception", "python:", ".py\", line",
    "error in ./", "/usr/lib/python", "/var/www/",
    "panic:", "stacktrace:", "fastapi", "flask", "express",
)

_DEFAULT_DEBUG_PATHS = (
    "/debug", "/debug/pprof", "/metrics", "/actuator",
    "/actuator/env", "/actuator/heapdump", "/.env", "/.git/config",
    "/swagger.json", "/openapi.json", "/graphql", "/trace",
    "/console", "/logs", "/status", "/health", "/ping",
    "/api/health", "/internal/", "/__debug__/",
    "/server-status", "/.aws/credentials",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "information_disclosure"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    probe_debug_paths = bool(params.get("probe_debug_paths", True))
    probe_tool_responses = bool(params.get("probe_tool_responses", True))
    validate = bool(params.get("validate_secrets", True))
    extra_debug_paths = params.get("extra_debug_paths") or []
    max_tools = int(params.get("max_tools_to_probe", 12))
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None

    # 1. Debug paths
    base = (target.get("base_url") or "").rstrip("/") or \
        f"{target.get('protocol','http')}://{target.get('host','localhost')}:{target.get('port',80)}"
    if probe_debug_paths:
        all_paths = list(_DEFAULT_DEBUG_PATHS) + list(extra_debug_paths)
        for path in all_paths:
            url = base + path
            try:
                r = requests.get(url, timeout=timeout, allow_redirects=False,
                                 verify=False)
            except Exception:
                continue
            if r.status_code < 400 and len(r.text or "") > 0:
                # Validate any secrets in the body too
                for s in secret_validators.detect_secrets(r.text):
                    _record_secret(rb, context, target,
                                    where=f"debug-path {path}",
                                    secret=s, body=r.text, validate=validate)
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "information_disclosure"),
                    title=f"Debug/management path exposed: {path}",
                    category="information_disclosure",
                    severity="high", confidence="confirmed",
                    cwe="CWE-200",
                    description=(
                        f"GET {url} returned HTTP {r.status_code} ({len(r.text)} "
                        "bytes). Debug paths must not be world-reachable."
                    ),
                    remediation=("Bind to localhost / VPC. Authenticate. "
                                 "Disable in production builds."),
                    payload=url,
                    evidence=[evidence.ev_http(
                        {"method": "GET", "url": url},
                        {"status": r.status_code, "headers": dict(r.headers),
                         "body": r.text[:2000]})],
                ))

    # 2. Banner / version headers
    try:
        r = requests.get(base + "/mcp", timeout=timeout, verify=False)
        headers = {k.lower(): v for k, v in r.headers.items()}
        for h in ("server", "x-powered-by", "x-aspnet-version",
                  "x-runtime", "x-rack", "x-php-version"):
            if h in headers and any(c.isdigit() for c in headers[h]):
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "information_disclosure"),
                    title=f"Version disclosed in '{h}' header",
                    category="information_disclosure",
                    severity="low", confidence="confirmed",
                    cwe="CWE-200",
                    description=f"{h}: {headers[h]}",
                    remediation="Strip server-version headers at the reverse proxy.",
                    payload=f"{h}: {headers[h]}",
                ))
    except Exception:
        pass

    # 3. MCP-side: verbose errors + secret leakage
    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        init = mcp.initialize()
        rb.add_evidence(evidence.ev_mcp_call(init, note="initialize"))
        if not init.get("ok"):
            rb.warn("Could not initialize for deep probes; skipping.")
            return rb.finalize(success=True)

        # Trigger an invalid call → does the server leak internals?
        bad = mcp.transport.send("tools/call", {"name": "___nope___",
                                                 "arguments": {"x": "."}})
        rb.add_evidence(evidence.ev_mcp_call(bad, note="invalid-tool error"))
        err = bad.get("error") or {}
        err_msg = str(err.get("message") or err.get("data") or bad.get("response"))
        if _looks_like_stack(err_msg):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "information_disclosure"),
                title="Stack trace / internal path leaked in MCP error",
                category="information_disclosure",
                severity="medium", confidence="confirmed",
                cwe="CWE-209",
                description=("Invalid tools/call returned an error containing "
                             f"stack-trace-like internals. Excerpt: {err_msg[:200]!r}"),
                remediation=("Wrap JSON-RPC handlers in a sanitizing layer. Log "
                             "tracebacks server-side only."),
                payload="tools/call name='___nope___'",
                evidence=[evidence.ev_mcp_call(bad)],
            ))

        # Secret scan across tool outputs
        if probe_tool_responses:
            tl = mcp.tools_list()
            if tl.get("ok"):
                tools = (tl.get("result") or {}).get("tools") or []
                for t in tools[:max_tools]:
                    name = t.get("name")
                    if not name:
                        continue
                    args = helpers.fill_defaults(t.get("inputSchema") or {})
                    r = mcp.call_tool_safe(name, args)
                    text = r.get("text_output") or ""
                    if not text:
                        continue
                    for s in secret_validators.detect_secrets(text):
                        _record_secret(rb, context, target,
                                        where=f"tool '{name}' response",
                                        secret=s, body=text, validate=validate,
                                        tool_name=name,
                                        tool_resp=r)
        return rb.finalize()
    finally:
        mcp.close()


def _record_secret(rb, context, target, *, where, secret, body, validate,
                    tool_name=None, tool_resp=None):
    typ = secret["type"]
    value = secret["value"]
    excerpt = (body[max(0, secret["span"][0] - 40): secret["span"][1] + 40]
                .replace("\n", " "))[:200]

    valid_result = None
    if validate:
        try:
            valid_result = secret_validators.validate(typ, value)
        except Exception as e:
            rb.warn(f"Validation of {typ} failed: {e!s:.200}")

    if valid_result and valid_result.get("valid") is True:
        sev = "critical"
        conf = "confirmed"
        title = f"VALID {typ} leaked from {where}"
        descr = (f"Discovered {typ} `{_redact(value)}` in {where}. "
                 f"Validated against issuer endpoint: {valid_result['summary']}")
    elif valid_result and valid_result.get("valid") is False:
        sev = "medium"
        conf = "high"
        title = f"INVALID {typ} pattern in {where}"
        descr = (f"Found `{_redact(value)}` matching {typ} format but issuer "
                 f"rejected it ({valid_result['summary']}). Likely a fixture / "
                 "expired token, but still indicates the codebase handles "
                 "real secrets in this code path.")
    else:
        sev = "high"
        conf = "medium"
        title = f"Suspected {typ} pattern in {where} (not validated)"
        descr = (f"Discovered string matching {typ} format in {where}. Could "
                 "not validate against issuer.")

    ev_items = [evidence.ev_raw("excerpt", excerpt)]
    if valid_result:
        ev_items.append(evidence.ev_raw("validation", valid_result))
    if tool_resp is not None:
        ev_items.append(evidence.ev_mcp_call(tool_resp, note="containing response"))

    rb.add_finding(evidence.Finding(
        attack_id=context.get("attack_id", "information_disclosure"),
        title=title,
        category="information_disclosure",
        severity=sev, confidence=conf,
        cwe="CWE-532",
        tool=tool_name,
        payload=_redact(value),
        description=descr,
        impact=("Live credential. Attacker can impersonate the secret's owner "
                "across every system that trusts this issuer."
                if conf == "confirmed"
                else "Credential-shaped string in production output."),
        remediation=("Never return raw credentials. Replace with opaque "
                     "reference IDs and resolve server-side. Rotate the secret."),
        evidence=ev_items,
    ))


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


def _looks_like_stack(msg):
    m = (msg or "").lower()
    return any(k in m for k in _STACK_MARKERS)
