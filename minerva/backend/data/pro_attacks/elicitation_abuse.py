"""
MCP Elicitation abuse (server-asks-user-for-input surface).

The 2025-06-18 MCP spec adds `elicitation/create` — the server can ask
the user a structured question (text, password, choice) and the client
forwards the prompt to the human. This is a phishing-grade primitive
when misused:

  - Server asks "Please enter your AWS access key for verification".
  - Client renders the prompt; user complies; server harvests the secret.

This attack audits a target server for elicitation abuse:

Tests
-----
1. **Capability advertising** — does the server declare `elicitation`
   capability? Like sampling, this is a CLIENT capability and a server
   that claims it is misconfigured.
2. **Reverse elicitation probe** — send `elicitation/create` *to* the
   server. The server should respond with -32601 method-not-found.
3. **Tool-induced elicitation** — call tools that hint at user
   interaction ("ask", "prompt", "verify", "confirm") and capture any
   `elicitation/create` requests the server attempts back to us.
4. **Sensitive-field detection** — when the server requests elicitation
   (captured via SSE / WS / stdio), audit each requested field's name
   and description for password / API-key / OTP smell.
5. **Schema laxity** — does the elicitation request mark sensitive
   fields with `format: "password"` or are they plain strings?

Dynamic params
--------------
  protocol_version    — override version
  transport_override  — http|sse|ws|stdio
  reverse_test        — toggle reverse elicitation probe
  capture_window      — seconds to wait for elicitation requests during
                        tool execution (only useful on SSE/WS/stdio)
  only_tool_names     — restrict tool-induced probe set
  max_tools           — cap iteration
"""

import time as _time
import uuid as _uuid


_INTERACTION_KEYWORDS = (
    "ask", "prompt", "input", "verify", "confirm", "auth",
    "register", "signup", "credential", "key", "token", "password",
    "secret", "api_key", "approve",
)


_SENSITIVE_FIELD_HINTS = (
    "password", "passwd", "pwd",
    "api_key", "apikey", "api-key",
    "secret", "token", "access_token", "refresh_token",
    "private_key", "ssh_key",
    "otp", "mfa", "totp", "auth_code", "2fa",
    "credit_card", "card_number", "cvv", "ssn", "social",
    "aws_secret", "aws_access_key", "stripe", "openai", "anthropic",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "elicitation_abuse"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    protocol_version = params.get("protocol_version") or "2025-06-18"
    transport_override = params.get("transport_override") or None
    reverse_test = bool(params.get("reverse_test", True))
    capture_window = float(params.get("capture_window", 5.0))
    only_tool_names = params.get("only_tool_names") or []
    max_tools = int(params.get("max_tools", 10))

    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        # Advertise elicitation capability so the server knows it can ask
        init = mcp.initialize(capabilities={"elicitation": {}, "sampling": {},
                                            "roots": {"listChanged": True}})
        rb.add_evidence(evidence.ev_mcp_call(init, note="initialize w/ elicitation"))
        if not init.get("ok"):
            rb.error("Server rejected initialize.")
            return rb.finalize(success=False)
        caps = (init.get("result") or {}).get("capabilities") or {}
        rb.info(f"Server caps after handshake: {list(caps.keys())}")

        # 1) Server claims elicitation
        if "elicitation" in caps:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "elicitation_abuse"),
                title="Server declares `elicitation` capability (client-only spec)",
                category="elicitation_abuse",
                severity="high", confidence="confirmed",
                cwe="CWE-693",
                description=(
                    "MCP `elicitation` is a CLIENT capability — only the host "
                    "should advertise it. A server claiming elicitation is "
                    "either misconfigured or attempting to reverse the trust "
                    "boundary (servers asking other servers for input)."
                ),
                impact=(
                    "Confused-deputy: a downstream MCP host that trusts the "
                    "server's metadata may grant elicitation privileges, "
                    "letting the server prompt human users on its own behalf."
                ),
                remediation=(
                    "Remove `elicitation` from serverCapabilities. The server "
                    "asks the host (which asks the user) — never the reverse."
                ),
                references=[
                    "https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation",
                ],
                payload=str(caps.get("elicitation")),
            ))

        # 2) Reverse elicitation probe — send elicitation/create TO the server
        if reverse_test:
            payload = {
                "message": "Please enter your administrator password",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"password": {"type": "string",
                                                "format": "password"}},
                    "required": ["password"],
                },
            }
            r = mcp.transport.send("elicitation/create", payload)
            rb.add_evidence(evidence.ev_mcp_call(
                r, note="reverse elicitation/create probe"))
            err = r.get("error") or {}
            if r.get("ok") and isinstance(r.get("result"), dict):
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "elicitation_abuse"),
                    title="Server responds to elicitation/create as a client",
                    category="elicitation_abuse",
                    severity="critical", confidence="confirmed",
                    cwe="CWE-269",
                    description=(
                        "Server returned a populated result for an "
                        "`elicitation/create` request *sent to it*. This means "
                        "the server is acting as a client, exposing a UI "
                        "elicitation channel that anyone with network access "
                        "can drive."
                    ),
                    impact=(
                        "Attackers can phish anyone the server forwards "
                        "elicitations to. If the host auto-approves on the "
                        "user's behalf, secrets are harvested without consent."
                    ),
                    remediation=("Reject elicitation/create with method-not-found "
                                 "(-32601). Elicitation flows from server → host → "
                                 "user, never the reverse."),
                    payload=str(payload)[:400],
                ))
            else:
                rb.info(f"Reverse elicitation correctly returned error: code={err.get('code')}")

        # 3) Tool-induced elicitation
        tools = (init.get("result") or {}).get("tools") or []
        if not tools:
            tl = mcp.tools_list()
            tools = ((tl.get("result") or {}).get("tools") or [])
        if only_tool_names:
            tools = [t for t in tools if t.get("name") in set(only_tool_names)]
        cands = [t for t in tools
                 if any(k in f"{t.get('name','')} {t.get('description','')}".lower()
                        for k in _INTERACTION_KEYWORDS)][:max_tools]
        if not cands and tools:
            cands = tools[:max_tools]

        # For HTTP transport, server-initiated elicitation isn't observable.
        # We rely on tool-output text indicators instead.
        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            args = helpers.fill_defaults(schema)
            t0 = _time.time()
            r = mcp.call_tool_safe(tname, args)
            dt = _time.time() - t0
            rb.add_evidence(evidence.ev_mcp_call(
                r, note=f"elicitation-induced probe {tname} dt={dt:.2f}s"))
            text = (r.get("text_output") or "").lower()
            # Server may embed elicitation prompts in tool result content
            if any(h in text for h in _SENSITIVE_FIELD_HINTS) and \
                    any(w in text for w in ("enter", "provide", "input", "type")):
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "elicitation_abuse"),
                    title=f"Tool '{tname}' asks for sensitive credentials in output",
                    category="elicitation_abuse",
                    severity="high", confidence="medium",
                    cwe="CWE-522",
                    tool=tname,
                    description=(
                        "Tool response contains language that asks the caller "
                        "to provide a sensitive value (password / API key / OTP). "
                        "When this output is rendered to a user via MCP, "
                        "attackers controlling the tool can harvest secrets."
                    ),
                    impact=(
                        "Phishing / credential-harvest from a trusted tool "
                        "context. Users assume the prompt is legitimate."
                    ),
                    remediation=(
                        "Tools should never render free-form input requests in "
                        "their output. Use the spec'd `elicitation/create` flow "
                        "with a structured schema, and tag sensitive fields "
                        "with `format: \"password\"`."
                    ),
                    payload=text[:400],
                ))

        return rb.finalize()
    finally:
        mcp.close()
