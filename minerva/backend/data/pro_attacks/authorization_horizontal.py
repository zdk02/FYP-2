"""
Authorization Horizontal — BOLA / IDOR for MCP (Pro).

OWASP API #1 (BOLA) is the single most prevalent API vulnerability in
the wild. MCP servers expose tools that take resource identifiers
(file_id, document_id, account_id, user_id, owner) and the server is
expected to enforce that the calling principal owns or can access that
resource. Frequently, they don't.

This attack tests for HORIZONTAL authz (same role, different principal):
authentication checks pass, but the server fails to verify ownership.

Modes
-----
1. Single-principal mode (default):
   - Discover tools whose inputSchema has ID-shaped parameters.
   - For each, call with mutated IDs (decrement, increment, ±UUIDs,
     "1", "0", "admin", common test fixture IDs).
   - If the tool returns DATA (not an error) for IDs that look unlike
     those issued to the current principal, flag IDOR.

2. Two-principal mode (requires `secondary_auth` param):
   - Run probe with primary auth → record returned IDs.
   - Re-run with secondary auth → record IDs.
   - Cross-call: ask primary to fetch a secondary-only ID; if it
     succeeds, CONFIRMED IDOR.

Confidence: confirmed in two-principal mode where cross-access succeeds;
high in single-principal mode where mutated IDs return non-error data
that differs from the legitimate response.
"""

import re as _re
import uuid as _uuid


_ID_PARAM_KEYWORDS = (
    "id", "uuid", "guid", "identifier",
    "user_id", "userid", "owner", "owner_id", "account_id", "accountid",
    "document_id", "doc_id", "file_id", "fileid",
    "resource_id", "resource", "key", "object_id", "objectid",
    "ticket", "ticket_id", "order_id", "order", "invoice_id", "invoice",
    "subject", "principal", "actor",
)


def _id_params(schema: dict) -> list[str]:
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties") or {}
    out = []
    for name in props:
        n = name.lower()
        if any(k == n or n.endswith(f"_{k}") or n.endswith(k) for k in _ID_PARAM_KEYWORDS):
            out.append(name)
    return out


def _safe_args_from_schema(schema: dict) -> dict:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    out = {}
    for name in required:
        spec = props.get(name) or {}
        t = spec.get("type")
        if t == "integer" or t == "number":
            out[name] = 1
        elif t == "boolean":
            out[name] = False
        elif t == "array":
            out[name] = []
        elif t == "object":
            out[name] = {}
        else:
            out[name] = "minerva"
    return out


def _mutate_id(value):
    """Generate plausible cross-principal ID candidates for `value`."""
    candidates = []
    sval = str(value or "")
    if sval.isdigit():
        n = int(sval)
        candidates += [str(n + 1), str(max(0, n - 1)), "0", "1", "9999"]
    if _re.fullmatch(r"[0-9a-fA-F-]{8,}", sval):
        candidates += [str(_uuid.uuid4()),
                       "00000000-0000-0000-0000-000000000000",
                       "11111111-1111-1111-1111-111111111111"]
    candidates += ["admin", "root", "test", "demo", "guest"]
    seen, uniq = set(), []
    for c in candidates:
        if c not in seen and c != sval:
            seen.add(c)
            uniq.append(c)
    return uniq[:8]


def _result_text(resp: dict) -> str:
    body = (resp.get("response") or {})
    if "error" in body:
        return ""  # error means access denied (good)
    result = body.get("result") or {}
    if not isinstance(result, dict):
        return repr(result)[:5000]
    if result.get("isError"):
        return ""
    bits = []
    for c in result.get("content") or []:
        if isinstance(c, dict) and c.get("type") == "text":
            bits.append(str(c.get("text") or ""))
    return ("\n".join(bits) or repr(result))[:5000]


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "authorization_horizontal"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    max_tools = int(params.get("max_tools", 15))
    max_mutations = int(params.get("max_mutations_per_param", 5))
    secondary_auth = params.get("secondary_auth")
    transport_override = params.get("transport_override") or None
    protocol_version = params.get("protocol_version") or None

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
        candidates = []
        for t in tools:
            schema = t.get("inputSchema") or {}
            ids = _id_params(schema)
            if ids:
                candidates.append((t, ids))
        candidates = candidates[:max_tools]
        rb.info(f"Found {len(candidates)} tool(s) with ID-shaped parameters.")

        for tool, id_params in candidates:
            tname = tool.get("name") or "?"
            schema = tool.get("inputSchema") or {}
            base_args = _safe_args_from_schema(schema)

            # Probe legitimate call to capture baseline
            for idp in id_params:
                base_args.setdefault(idp, "1")
            base_resp = mcp_client.call(
                target, "tools/call",
                {"name": tname, "arguments": base_args},
                timeout=timeout,
            )
            base_text = _result_text(base_resp)

            for idp in id_params:
                seed_value = base_args.get(idp) or "1"
                mutations = _mutate_id(seed_value)[:max_mutations]
                for m in mutations:
                    args2 = dict(base_args)
                    args2[idp] = m
                    resp2 = mcp_client.call(
                        target, "tools/call",
                        {"name": tname, "arguments": args2},
                        timeout=timeout,
                    )
                    text2 = _result_text(resp2)
                    body2 = resp2.get("response") or {}
                    if not text2 or "error" in body2:
                        continue
                    # Got data for a mutated ID — heuristic IDOR
                    if text2 != base_text:
                        f = evidence.Finding(
                            attack_id=context.get("attack_id", "authorization_horizontal"),
                            title=f"Possible IDOR: tool {tname!r} returns data for mutated {idp}={m!r}",
                            category="authorization_horizontal",
                            severity="high", confidence="high",
                            tool=tname,
                            parameter=idp,
                            payload=str(m),
                            description=(
                                f"With the same authentication, calling tool "
                                f"{tname!r} with {idp}={m!r} (mutated from "
                                f"baseline) returned a non-error response that "
                                f"differs from the baseline. The server is not "
                                f"verifying that the calling principal owns the "
                                f"resource referenced by {idp}."
                            ),
                            impact=(
                                "Authenticated attacker can read other users' "
                                "data by guessing or enumerating IDs."
                            ),
                            remediation=(
                                "Enforce object-level authorization: every tool "
                                "that accepts an ID must verify the calling "
                                "principal has access to that specific resource."
                            ),
                            cwe="CWE-639",
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                                "https://cwe.mitre.org/data/definitions/639.html",
                            ],
                        )
                        f.add_evidence(evidence.ev_mcp_call(base_resp, note="baseline (legitimate ID)"))
                        f.add_evidence(evidence.ev_mcp_call(resp2, note=f"mutated {idp}={m}"))
                        rb.add_finding(f)

            # ----------------------------------------------------------
            # Two-principal mode
            # ----------------------------------------------------------
            if secondary_auth:
                t2 = dict(target)
                t2["auth_config"] = secondary_auth
                mcp2 = mcp_client.MCPClient.from_target(t2, timeout=timeout)
                try:
                    disc2 = mcp2.discover()
                    if not disc2["initialized"]:
                        rb.warn("Two-principal: secondary auth failed to initialize")
                    else:
                        # Call tool with secondary args (looking for an ID
                        # in returned data we can replay against primary)
                        secondary_resp = mcp_client.call(
                            t2, "tools/call",
                            {"name": tname, "arguments": base_args},
                            timeout=timeout,
                        )
                        s_text = _result_text(secondary_resp)
                        # Extract an ID from the secondary's response
                        ids_in_resp = _re.findall(
                            r"[0-9a-fA-F]{8}-?[0-9a-fA-F]{4,}|\b\d{4,}\b",
                            s_text,
                        )[:3]
                        for sid in ids_in_resp:
                            args3 = dict(base_args)
                            args3[id_params[0]] = sid
                            resp3 = mcp_client.call(
                                target, "tools/call",
                                {"name": tname, "arguments": args3},
                                timeout=timeout,
                            )
                            text3 = _result_text(resp3)
                            if text3 and "error" not in (resp3.get("response") or {}):
                                f = evidence.Finding(
                                    attack_id=context.get("attack_id", "authorization_horizontal"),
                                    title=f"CONFIRMED IDOR: primary token reads secondary's resource via tool {tname!r}",
                                    category="authorization_horizontal",
                                    severity="critical", confidence="confirmed",
                                    tool=tname,
                                    parameter=id_params[0],
                                    payload=sid,
                                    description=(
                                        f"Two-principal cross-access verified: tool "
                                        f"{tname!r} returned data for an ID "
                                        f"{sid!r} that was issued under a different "
                                        f"principal. Server is not enforcing "
                                        f"object-level authorization."
                                    ),
                                    impact="Authenticated attacker can read any user's data.",
                                    remediation="Enforce object-level authorization on every tool.",
                                    cwe="CWE-639",
                                )
                                f.add_evidence(evidence.ev_mcp_call(secondary_resp, note="secondary baseline"))
                                f.add_evidence(evidence.ev_mcp_call(resp3, note="primary cross-access"))
                                rb.add_finding(f)
                finally:
                    try:
                        mcp2.close()
                    except Exception:
                        pass

        return rb.finalize()
    finally:
        try:
            mcp.close()
        except Exception:
            pass
