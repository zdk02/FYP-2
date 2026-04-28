"""
File-Based Injection (Deletion) — detects tools that can delete files
at attacker-controlled paths. Non-destructive: attempts to delete a
non-existent path; if the server responds "not found" instead of
"forbidden / path outside sandbox", it would have deleted a real file.

Params:
  timeout:          int (default 15)
  sandbox_path:     str (default "/tmp") — base path for the ghost probe
  only_tool_names:  list[str]
"""

import uuid as _uuid


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "fbi_del"), target)
    timeout = int(params.get("timeout", 15))
    sandbox = str(params.get("sandbox_path") or "/tmp").rstrip("/\\")
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

        del_kw = ("delete", "remove", "unlink", "rm", "destroy", "purge")
        deleters = helpers.pick_by_keywords(disc.get("tools") or [], del_kw,
                                            force_names=only_tools)
        if not deleters:
            rb.warn("No delete-like tools."); return rb.finalize(success=True)

        for d in deleters[:5]:
            name = d.get("name")
            schema = d.get("inputSchema") or {}
            str_params = helpers.string_params(schema)
            if not str_params:
                continue
            path_p = next((p for p in str_params
                           if any(k in p.lower()
                                  for k in ("path", "file", "name"))),
                          str_params[0])
            ghost = f"{sandbox}/minerva_ghost_{_uuid.uuid4().hex[:8]}.tmp"
            args = helpers.fill_defaults(schema); args[path_p] = ghost
            r = mcp.call_tool_safe(name, args)
            rb.add_evidence(evidence.ev_mcp_call(
                r, note=f"ghost-delete {name}"))
            text = (r.get("text_output") or "").lower()
            if not r.get("is_error") and ("not found" in text or
                                           "no such" in text or
                                           "does not exist" in text):
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "fbi_del"),
                    title=f"Arbitrary file deletion primitive in '{name}'",
                    category="file_injection_deletion",
                    severity="high", confidence="high", cwe="CWE-73",
                    tool=name, parameter=path_p, payload=ghost,
                    description=(
                        "The tool returns a 'file not found' error for a "
                        "non-existent path — meaning it DOES accept "
                        "arbitrary paths and would delete them if present. "
                        "An authorised path-check should instead return "
                        "'forbidden' or 'path outside sandbox'."
                    ),
                    impact=(
                        "Attacker can delete any file the server process "
                        "can reach — logs (cover tracks), config (cause "
                        "outage), SSH keys (lock out admins)."
                    ),
                    remediation=(
                        "Validate target path is inside an allowed base "
                        "before any stat/delete. Return 'forbidden' (not "
                        "'not found') for out-of-scope paths to prevent "
                        "path-probing."
                    ),
                ))
        return rb.finalize()
    finally:
        mcp.close()
