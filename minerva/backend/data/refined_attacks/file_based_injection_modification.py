"""
File-Based Injection (Modification) — confirms overwrite semantics by
writing v1, writing v2 to the same path, and checking read-back
reflects v2 (not v1).

Params:
  timeout:          int (default 20)
  sandbox_path:     str (default "/tmp")
  only_tool_names:  list[str]
"""

import uuid as _uuid


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "fbi_mod"), target)
    timeout = int(params.get("timeout", 20))
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

        writers = helpers.pick_by_keywords(
            disc.get("tools") or [],
            ("write", "update", "save", "overwrite", "put", "modify", "edit"),
            force_names=only_tools)
        readers = helpers.pick_by_keywords(
            disc.get("tools") or [],
            ("read", "get", "fetch", "cat", "load"))
        if not writers or not readers:
            rb.warn("Need write + read tools.")
            return rb.finalize(success=True)

        path = f"{sandbox}/minerva_mod_{_uuid.uuid4().hex[:8]}.txt"
        v1 = "VER1_" + _uuid.uuid4().hex[:8]
        v2 = "VER2_" + _uuid.uuid4().hex[:8]

        for w in writers[:3]:
            schema = w.get("inputSchema") or {}
            sp = helpers.string_params(schema)
            if len(sp) < 2:
                continue
            pth = next((p for p in sp
                        if any(k in p.lower()
                               for k in ("path", "file", "name"))), sp[0])
            ctn = next((p for p in sp
                        if p != pth
                        and any(k in p.lower()
                                for k in ("content", "data", "body", "text"))),
                       sp[1])
            a1 = helpers.fill_defaults(schema); a1[pth] = path; a1[ctn] = v1
            mcp.call_tool_safe(w.get("name"), a1)
            a2 = helpers.fill_defaults(schema); a2[pth] = path; a2[ctn] = v2
            r2 = mcp.call_tool_safe(w.get("name"), a2)
            rb.add_evidence(evidence.ev_mcp_call(
                r2, note=f"overwrite via {w.get('name')}"))
            for rd in readers[:3]:
                rsc = rd.get("inputSchema") or {}
                rp = helpers.string_params(rsc)
                if not rp:
                    continue
                rpath = next((p for p in rp
                              if any(k in p.lower()
                                     for k in ("path", "file"))), rp[0])
                ra = helpers.fill_defaults(rsc); ra[rpath] = path
                rr = mcp.call_tool_safe(rd.get("name"), ra)
                txt = rr.get("text_output") or ""
                if v2 in txt and v1 not in txt:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "fbi_mod"),
                        title=(f"Arbitrary file overwrite confirmed on "
                               f"'{w.get('name')}'"),
                        category="file_injection_modification",
                        severity="critical", confidence="confirmed",
                        cwe="CWE-73", tool=w.get("name"),
                        payload=path,
                        description=(
                            f"Two successive writes replaced file contents "
                            f"at '{path}'. Read-back returns the latest "
                            "version only — overwrite semantics confirmed."
                        ),
                        impact=(
                            "Attacker can replace critical system files "
                            "(config, cron, shell profiles, SSH "
                            "authorized_keys)."
                        ),
                        remediation=(
                            "Scope writes to a sandbox directory; require "
                            "explicit 'create' vs 'overwrite' semantics; "
                            "reject overwrite of paths not owned by the "
                            "tool's user namespace."
                        ),
                        evidence=[evidence.ev_mcp_call(r2),
                                  evidence.ev_mcp_call(rr)],
                    ))
                    return rb.finalize()
        return rb.finalize()
    finally:
        mcp.close()
