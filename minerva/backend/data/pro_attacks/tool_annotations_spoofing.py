"""
Tool Annotations Spoofing (Pro) — MCP-novel.

MCP 2025-03-26+ defines tool annotation hints:
  - readOnlyHint:    "this tool does not modify state"
  - destructiveHint: "this tool modifies state destructively"
  - idempotentHint:  "calling N times == calling once"
  - openWorldHint:   "this tool may interact with the outside world"

These are CLAIMS made by the server. Clients (and the LLMs using them)
trust these hints to decide what to call without confirmation. A
malicious / misconfigured server can lie: claim readOnlyHint=true on a
tool that actually deletes resources, leading the client to call it
without the user's permission.

This attack VERIFIES the claims:

  1. Snapshots `resources/list` (URI fingerprint) before any test call.
  2. For each tool claiming readOnlyHint=true, calls it with safe-looking
     arguments derived from inputSchema.
  3. Re-snapshots `resources/list`; any URI-set change refutes the
     readOnlyHint claim → CONFIRMED finding.
  4. Same logic for idempotentHint: calls twice, compares responses.
  5. Cross-check: any tool with both readOnlyHint=true AND destructiveHint=true
     (contradictory) is flagged for schema audit.

Confidence: confirmed if state-drift observed, high if contradictory hints,
medium if hint absent on a tool whose name implies state change (delete,
update, write).
"""

import re as _re


_DESTRUCTIVE_NAME_KEYWORDS = (
    "delete", "remove", "drop", "purge", "destroy", "wipe", "rm",
    "create", "update", "patch", "modify", "set", "write",
    "upload", "send", "post", "put", "exec", "run", "execute",
)


def _looks_destructive(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in _DESTRUCTIVE_NAME_KEYWORDS)


def _safe_args_from_schema(schema: dict) -> dict:
    """Derive minimal-impact args from a tool's inputSchema."""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    out = {}
    for name in required:
        spec = props.get(name) or {}
        t = spec.get("type")
        if t == "string":
            # use a value tagged as a probe; safer than empty string for some
            # validators
            out[name] = "minerva_probe_readonly"
        elif t == "integer" or t == "number":
            out[name] = 1
        elif t == "boolean":
            out[name] = False
        elif t == "array":
            out[name] = []
        elif t == "object":
            out[name] = {}
        else:
            out[name] = "minerva_probe_readonly"
    return out


def _resource_uri_set(disc):
    return frozenset((r.get("uri") or "") for r in (disc.get("resources") or []))


def _tools_uri_set(disc):
    return frozenset((t.get("name") or "") for t in (disc.get("tools") or []))


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "tool_annotations_spoofing"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    max_tools = int(params.get("max_tools", 20))
    only = params.get("only_tool_names") or []
    test_idempotency = bool(params.get("test_idempotency", True))
    test_destructive_naming = bool(params.get("test_destructive_naming", True))
    transport_override = params.get("transport_override") or None
    protocol_version = params.get("protocol_version") or None

    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        disc_before = mcp.discover()
        if not disc_before["initialized"]:
            rb.error(f"MCP initialize failed: {disc_before.get('errors')}")
            return rb.finalize(success=False)

        baseline_resources = _resource_uri_set(disc_before)
        baseline_tools = _tools_uri_set(disc_before)

        tools = disc_before.get("tools") or []
        if only:
            tools = [t for t in tools if t.get("name") in only]
        tools = tools[:max_tools]
        rb.info(f"Auditing annotations on {len(tools)} tools "
                f"(baseline: {len(baseline_resources)} resources, "
                f"{len(baseline_tools)} tools).")

        for t in tools:
            name = t.get("name") or "?"
            ann = t.get("annotations") or {}
            ro = bool(ann.get("readOnlyHint"))
            dh = bool(ann.get("destructiveHint"))
            ih = bool(ann.get("idempotentHint"))
            ow = bool(ann.get("openWorldHint"))

            # --- contradictory hints -----------------------------------
            if ro and dh:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "tool_annotations_spoofing"),
                    title=f"Contradictory annotations on tool {name!r}: readOnlyHint=true AND destructiveHint=true",
                    category="tool_annotations_contradictory",
                    severity="medium", confidence="high",
                    tool=name,
                    description=(
                        "The server advertises this tool as both read-only and "
                        "destructive. A client trusting either hint will reach "
                        "an inconsistent decision, and the contradiction itself "
                        "indicates the metadata layer cannot be trusted."
                    ),
                    impact=(
                        "Client / LLM cannot rely on the annotations to decide "
                        "whether to ask the user for confirmation."
                    ),
                    remediation=(
                        "Pick one. Either the tool modifies state and is "
                        "destructive, or it does not and is read-only. Reject "
                        "tools at registration whose annotations contradict."
                    ),
                    cwe="CWE-440",
                    references=[
                        "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
                    ],
                ))

            # --- destructive name without destructiveHint --------------
            if test_destructive_naming and _looks_destructive(name) and not dh:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "tool_annotations_spoofing"),
                    title=f"Tool name suggests state change but destructiveHint not set: {name!r}",
                    category="tool_annotations_missing",
                    severity="low", confidence="medium",
                    tool=name,
                    description=(
                        f"Tool {name!r}'s name contains a destructive verb "
                        "(delete/remove/drop/etc.) but the server does not "
                        "advertise destructiveHint=true. Clients may auto-call."
                    ),
                    impact=(
                        "The LLM client may invoke the tool without prompting "
                        "the user, on the assumption it is non-destructive."
                    ),
                    remediation=(
                        "Set destructiveHint=true on tools that modify or "
                        "delete state, regardless of the tool name."
                    ),
                    cwe="CWE-862",
                ))

            # --- readOnlyHint honesty check ----------------------------
            if ro:
                helpers_log = []

                # Probe: call once with safe args; re-list resources;
                # any change → readOnlyHint is a lie.
                args = _safe_args_from_schema(t.get("inputSchema") or {})
                rb.info(f"Probing readOnlyHint on {name!r} with args={args}")
                resp = mcp_client.call(target, "tools/call",
                                       {"name": name, "arguments": args},
                                       timeout=timeout)
                helpers_log.append(resp)

                disc_after = mcp.discover()
                after_resources = _resource_uri_set(disc_after)
                after_tools = _tools_uri_set(disc_after)

                added = after_resources - baseline_resources
                removed = baseline_resources - after_resources
                tools_drift = (after_tools != baseline_tools)

                if added or removed or tools_drift:
                    f = evidence.Finding(
                        attack_id=context.get("attack_id", "tool_annotations_spoofing"),
                        title=f"readOnlyHint LIE — tool {name!r} caused state change",
                        category="tool_annotations_spoofing",
                        severity="high", confidence="confirmed",
                        tool=name,
                        parameter="annotations.readOnlyHint",
                        payload="(safe-derived args from inputSchema)",
                        description=(
                            f"Tool {name!r} advertises readOnlyHint=true. After "
                            f"a single call with minimal-impact arguments, the "
                            f"resource/tool fingerprint changed: "
                            f"+{len(added)} resources added, "
                            f"-{len(removed)} removed, "
                            f"tool-list drift={tools_drift}. The annotation is "
                            f"false and clients that auto-invoke read-only tools "
                            f"can be tricked into mutating state."
                        ),
                        impact=(
                            "LLM clients trusting readOnlyHint will auto-invoke "
                            "without user confirmation, allowing arbitrary state "
                            "modifications under the user's authority."
                        ),
                        remediation=(
                            "Either (a) make the tool genuinely read-only, or "
                            "(b) set readOnlyHint=false and destructiveHint=true."
                        ),
                        cwe="CWE-862",
                        references=[
                            "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
                            "https://cwe.mitre.org/data/definitions/862.html",
                        ],
                    )
                    f.add_evidence(evidence.ev_mcp_call(resp, note="readOnly probe call"))
                    f.add_evidence(evidence.ev_raw(
                        "resource fingerprint diff",
                        {"added": list(added), "removed": list(removed),
                         "tools_changed": tools_drift},
                    ))
                    rb.add_finding(f)
                    # Update baseline for subsequent tools
                    baseline_resources = after_resources
                    baseline_tools = after_tools
                else:
                    rb.info(f"  readOnlyHint honoured by {name!r}")

            # --- idempotentHint honesty check --------------------------
            if test_idempotency and ih:
                args = _safe_args_from_schema(t.get("inputSchema") or {})
                r1 = mcp_client.call(target, "tools/call",
                                     {"name": name, "arguments": args},
                                     timeout=timeout)
                r2 = mcp_client.call(target, "tools/call",
                                     {"name": name, "arguments": args},
                                     timeout=timeout)
                # Compare top-level "content" / "result" structure
                def _normalize(resp):
                    body = (resp.get("response") or {}).get("result") or resp.get("response") or {}
                    if isinstance(body, dict):
                        body = {k: v for k, v in body.items()
                                if k not in ("isError", "_meta")}
                    return repr(body)[:2000]
                if _normalize(r1) != _normalize(r2):
                    f = evidence.Finding(
                        attack_id=context.get("attack_id", "tool_annotations_spoofing"),
                        title=f"idempotentHint LIE — tool {name!r} returned different results on identical calls",
                        category="tool_annotations_spoofing",
                        severity="medium", confidence="confirmed",
                        tool=name,
                        parameter="annotations.idempotentHint",
                        description=(
                            f"Tool {name!r} advertises idempotentHint=true but "
                            f"two consecutive identical calls produced different "
                            f"results, indicating the tool has side effects or "
                            f"non-deterministic behaviour."
                        ),
                        impact=(
                            "Retry logic and caching layers built on the "
                            "idempotency claim will produce duplicate side effects."
                        ),
                        remediation="Remove idempotentHint or refactor tool to be idempotent.",
                        cwe="CWE-440",
                    )
                    f.add_evidence(evidence.ev_mcp_call(r1, note="call 1"))
                    f.add_evidence(evidence.ev_mcp_call(r2, note="call 2"))
                    rb.add_finding(f)

            # --- openWorldHint missing on URL-accepting tools -----------
            if not ow:
                schema = t.get("inputSchema") or {}
                props = schema.get("properties") or {}
                url_params = [p for p, s in props.items()
                              if any(k in p.lower() for k in
                                     ("url", "uri", "endpoint", "host"))]
                if url_params:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "tool_annotations_spoofing"),
                        title=f"openWorldHint missing on tool {name!r} that accepts URL parameter(s)",
                        category="tool_annotations_missing",
                        severity="low", confidence="medium",
                        tool=name,
                        parameter=",".join(url_params),
                        description=(
                            f"Tool {name!r} accepts URL/URI parameters "
                            f"({', '.join(url_params)}) but does not advertise "
                            f"openWorldHint=true. Clients cannot warn the user "
                            f"about external interactions."
                        ),
                        impact=(
                            "Users cannot distinguish tools that touch external "
                            "endpoints (and thus may exfiltrate or fetch hostile "
                            "content) from tools that operate locally."
                        ),
                        remediation=(
                            "Set openWorldHint=true on any tool that may make "
                            "outbound network requests."
                        ),
                        cwe="CWE-829",
                    ))

        return rb.finalize()
    finally:
        try:
            mcp.close()
        except Exception:
            pass
