"""
File-Based Injection (Retrieval) — directory-enumeration probe. Tests
whether read/list tools accept arbitrary paths + wildcards and leak
host filesystem structure.

Params:
  timeout:          int (default 20)
  probe_paths:      list[str] — paths to try (default covers Linux + Windows)
  only_tool_names:  list[str]
"""


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "fbi_get"), target)
    timeout = int(params.get("timeout", 20))
    probe_paths = params.get("probe_paths") or [
        "/", "/etc", "C:\\", "*", ".", ".."]
    only_tools = params.get("only_tool_names") or []

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

        readers = helpers.pick_by_keywords(
            disc.get("tools") or [],
            ("list", "ls", "read", "dir", "tree", "scan", "browse"),
            force_names=only_tools)
        if not readers:
            rb.warn("No listing tools."); return rb.finalize(success=True)

        markers = ("bin/", "etc/", "usr/", "var/", "root/", "home/",
                   "Program Files", "Windows", "Users\\")

        for r in readers[:5]:
            schema = r.get("inputSchema") or {}
            sp = helpers.string_params(schema)
            if not sp:
                continue
            path_p = next((p for p in sp
                           if any(k in p.lower()
                                  for k in ("path", "dir", "folder"))), sp[0])
            for probe in probe_paths:
                args = helpers.fill_defaults(schema); args[path_p] = probe
                resp = mcp.call_tool_safe(r.get("name"), args)
                text = (resp.get("text_output") or "")
                rb.add_evidence(evidence.ev_mcp_call(
                    resp, note=f"dir probe {r.get('name')}[{path_p}]={probe}"))
                hit = helpers.contains_any(text, markers)
                if resp.get("ok") and not resp.get("is_error") and hit:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "fbi_get"),
                        title=(f"Directory enumeration possible via "
                               f"'{r.get('name')}' (probe='{probe}')"),
                        category="file_injection_retrieval",
                        severity="high", confidence="high", cwe="CWE-548",
                        tool=r.get("name"), parameter=path_p, payload=probe,
                        description=(
                            "The tool returned directory-listing content for "
                            f"the probe path '{probe}'. Attacker can "
                            "enumerate the filesystem to find valuable "
                            "files before exfiltrating them."
                        ),
                        impact=(
                            "Reconnaissance primitive. Often chains with a "
                            "path-traversal read to extract specific files."
                        ),
                        remediation=(
                            "Restrict listing to a configured sandbox root; "
                            "reject wildcards and parent references; "
                            "canonicalise paths before use."
                        ),
                        evidence=[evidence.ev_mcp_call(resp)],
                    ))
                    return rb.finalize()
        return rb.finalize()
    finally:
        mcp.close()
