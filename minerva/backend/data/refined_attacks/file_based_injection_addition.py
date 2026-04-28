"""
File-Based Injection (Addition) — detects tools that will write/create
files at arbitrary paths. Writes a canary at a configurable sandbox
path, reads it back through any read-like tool to confirm round-trip.

Params:
  timeout:            int (default 20)
  sandbox_path:       str (default "/tmp") — use "C:/Windows/Temp" or similar for Windows MCPs
  max_write_tools:    int (default 5)
  only_tool_names:    list[str] — if set, only these tools are probed
"""

import uuid as _uuid


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "fbi_add"), target)
    timeout = int(params.get("timeout", 20))
    sandbox = str(params.get("sandbox_path") or "/tmp").rstrip("/\\")
    max_write_tools = int(params.get("max_write_tools", 5))
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

        write_kw = ("write", "create", "save", "upload", "put", "add")
        writers = helpers.pick_by_keywords(disc.get("tools") or [], write_kw,
                                           force_names=only_tools)
        readers = helpers.pick_by_keywords(disc.get("tools") or [],
                                           ("read", "get", "fetch", "cat"))
        if not writers:
            rb.warn("No write-like tools."); return rb.finalize(success=True)

        canary_name = f"{sandbox}/minerva_canary_{_uuid.uuid4().hex[:8]}.txt"
        canary_content = f"MINERVA_CAN_{_uuid.uuid4().hex[:12]}"
        rb.info(f"Canary path: {canary_name}")

        for w in writers[:max_write_tools]:
            schema = w.get("inputSchema") or {}
            str_params = helpers.string_params(schema)
            if len(str_params) < 2:
                continue   # need path + content
            path_p = next((p for p in str_params
                           if any(k in p.lower()
                                  for k in ("path", "file", "name"))), str_params[0])
            content_p = next((p for p in str_params
                              if p != path_p
                              and any(k in p.lower()
                                      for k in ("content", "data", "body", "text"))),
                             str_params[1])
            args = helpers.fill_defaults(schema)
            args[path_p] = canary_name
            args[content_p] = canary_content
            r = mcp.call_tool_safe(w.get("name"), args)
            rb.add_evidence(evidence.ev_mcp_call(
                r, note=f"write canary via {w.get('name')}"))
            if not r.get("ok") or r.get("is_error"):
                continue
            # Try to read it back
            for reader in readers[:3]:
                rschema = reader.get("inputSchema") or {}
                read_params = helpers.string_params(rschema)
                if not read_params:
                    continue
                pp = next((p for p in read_params
                           if any(k in p.lower()
                                  for k in ("path", "file"))), read_params[0])
                ra = helpers.fill_defaults(rschema)
                ra[pp] = canary_name
                rr = mcp.call_tool_safe(reader.get("name"), ra)
                if canary_content in (rr.get("text_output") or ""):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "fbi_add"),
                        title=(f"Arbitrary file write on '{w.get('name')}' — "
                               "confirmed via read-back"),
                        category="file_injection_addition",
                        severity="critical", confidence="confirmed",
                        cwe="CWE-73", tool=w.get("name"),
                        payload=canary_name,
                        description=(
                            f"File '{canary_name}' written and successfully "
                            f"read back via '{reader.get('name')}'. The tool "
                            "places attacker-controlled content at attacker-"
                            "controlled paths."
                        ),
                        impact=(
                            "Chain into RCE (drop cron / systemd unit / "
                            ".bashrc), credential theft (write an SSH key), "
                            "or lateral movement."
                        ),
                        remediation=(
                            "Resolve paths with realpath(); reject anything "
                            "outside a designated upload directory; deny "
                            "filenames starting with '.' or containing '..'."
                        ),
                        evidence=[evidence.ev_mcp_call(r),
                                  evidence.ev_mcp_call(rr)],
                    ))
                    return rb.finalize()
        return rb.finalize()
    finally:
        mcp.close()
