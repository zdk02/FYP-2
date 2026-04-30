"""
MCP Schema Type Confusion.

Each MCP tool publishes an `inputSchema` (JSON Schema). The server then
validates incoming `tools/call` arguments against that schema — or it
*should*. In practice, many implementations:

  - Skip validation entirely (use the args dict directly).
  - Validate types loosely (str(arg)).
  - Reject extras at the top level but pass nested objects through.
  - Coerce types and miss the original-type-specific bug
    (e.g. `1` vs `"1"` reaches different code paths).

Tests
-----
1. **Type-mismatch** — for every parameter, send the wrong JSON type
   (string→object, integer→string, integer→array, boolean→string).
   Catalogue which tools accept it (and how the server responds).
2. **Numeric overflow** — send Number.MAX_SAFE_INTEGER+1, INT64 max,
   negative-zero, NaN, Infinity. Detect crashes / weird arithmetic.
3. **Deep / wide structures** — JSON nesting 200 deep, arrays of 50k
   items. Detect parser limits + downstream effects.
4. **Extra properties** — send an arg that isn't in the schema.
   `additionalProperties: false` should reject; many servers don't.
5. **Polymorphic confusion** — for `oneOf`/`anyOf` schemas, send a
   value that satisfies multiple branches.
6. **Required-field omission** — drop a `required` field; verify
   server rejects.
7. **Empty / null** — `null` for a string, empty string for a required
   field. Servers often crash here.

Findings are graded by severity:
  - confirmed crash / 5xx → high
  - schema bypass without crash → medium (information value)
  - successful arg with extra prop → medium

Dynamic params
--------------
  protocol_version, transport_override
  only_tool_names, max_tools
  test_overflow, test_deep_nesting, test_extras, test_required, test_oneof
  max_nesting_depth, max_array_size
"""

import json as _json
import time as _time


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "schema_type_confusion"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    protocol_version = params.get("protocol_version") or None
    transport_override = params.get("transport_override") or None
    only_tool_names = params.get("only_tool_names") or []
    max_tools = int(params.get("max_tools", 25))
    test_overflow = bool(params.get("test_overflow", True))
    test_deep_nesting = bool(params.get("test_deep_nesting", True))
    test_extras = bool(params.get("test_extras", True))
    test_required = bool(params.get("test_required", True))
    test_oneof = bool(params.get("test_oneof", True))
    max_nesting_depth = int(params.get("max_nesting_depth", 200))
    max_array_size = int(params.get("max_array_size", 5000))

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
        rb.info(f"Probing {len(cands)} tools for schema confusion")

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            props = (schema.get("properties") or {})
            required = list(schema.get("required") or [])
            additional = schema.get("additionalProperties")

            if not props:
                continue

            # 1) Type mismatch per param
            for pname, pspec in props.items():
                ptype = (pspec or {}).get("type")
                wrong_values = _wrong_type_values(ptype)
                for label, value in wrong_values:
                    args = helpers.fill_defaults(schema)
                    args[pname] = value
                    t0 = _time.time()
                    r = mcp.call_tool_safe(tname, args)
                    dt = _time.time() - t0
                    rb.add_evidence(evidence.ev_mcp_call(
                        r, note=f"type-confusion {tname}/{pname} {label}"))
                    if _looks_like_crash(r, dt):
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "schema_type_confusion"),
                            title=f"Type confusion crash in '{tname}/{pname}' ({label})",
                            category="schema_type_confusion",
                            severity="high", confidence="confirmed",
                            cwe="CWE-704",
                            tool=tname, parameter=pname,
                            payload=f"{label}={value!r}",
                            description=(
                                f"Sending a {label} value where schema expects "
                                f"{ptype!r} produced a 5xx-style failure or "
                                f"unhandled exception. Indicates the server skips "
                                f"schema validation."
                            ),
                            impact=(
                                "Schema-validation gaps frequently double as "
                                "downstream-injection gaps (SQLi, command injection, "
                                "deserialization)."
                            ),
                            remediation=(
                                "Validate `params.arguments` against `inputSchema` "
                                "before dispatching. Use a schema-validation library "
                                "with strict mode."
                            ),
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                    elif r.get("ok") and not r.get("is_error"):
                        # Server accepted wrong-type arg without erroring
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "schema_type_confusion"),
                            title=f"Server accepts wrong-type arg in '{tname}/{pname}' ({label})",
                            category="schema_type_confusion",
                            severity="medium", confidence="medium",
                            cwe="CWE-20",
                            tool=tname, parameter=pname,
                            payload=f"{label}={str(value)[:100]}",
                            description=(
                                f"Schema declares `{pname}: {ptype}`. Sent {label}; "
                                "server returned ok=true without an isError flag. "
                                "Type validation is missing."
                            ),
                            remediation="As above — strict schema validation.",
                        ))

            # 2) Numeric overflow on integer / number params
            if test_overflow:
                num_params = [n for n, s in props.items()
                              if isinstance(s, dict)
                              and s.get("type") in ("integer", "number")]
                for pname in num_params:
                    for label, value in [
                        ("INT64_MAX", 9223372036854775807),
                        ("INT64_MAX_PLUS_1", 9223372036854775808),
                        ("MIN_SAFE_INT", -9007199254740992),
                        ("NEG_INF",  -1e309),
                        ("NAN_STR",  "NaN"),
                    ]:
                        args = helpers.fill_defaults(schema)
                        args[pname] = value
                        r = mcp.call_tool_safe(tname, args)
                        rb.add_evidence(evidence.ev_mcp_call(
                            r, note=f"overflow {tname}/{pname} {label}"))
                        if _looks_like_crash(r, 0):
                            rb.add_finding(evidence.Finding(
                                attack_id=context.get("attack_id", "schema_type_confusion"),
                                title=f"Numeric overflow crash in '{tname}/{pname}' ({label})",
                                category="schema_type_confusion",
                                severity="medium", confidence="confirmed",
                                cwe="CWE-190",
                                tool=tname, parameter=pname, payload=str(value),
                                description="Server crashed on overflow value.",
                                remediation="Apply minimum/maximum constraints.",
                            ))

            # 3) Deep nesting / oversized arrays — find an object/array param
            if test_deep_nesting:
                for pname, pspec in props.items():
                    t = (pspec or {}).get("type")
                    if t == "object":
                        big = _nested_object(max_nesting_depth)
                        args = helpers.fill_defaults(schema)
                        args[pname] = big
                        t0 = _time.time()
                        r = mcp.call_tool_safe(tname, args)
                        dt = _time.time() - t0
                        rb.add_evidence(evidence.ev_mcp_call(
                            r, note=f"deep-nest {tname}/{pname} depth={max_nesting_depth}"))
                        if _looks_like_crash(r, dt) or dt > timeout * 0.8:
                            rb.add_finding(evidence.Finding(
                                attack_id=context.get("attack_id", "schema_type_confusion"),
                                title=f"Deep-JSON DoS / parser exhaustion in '{tname}/{pname}'",
                                category="schema_type_confusion",
                                severity="medium", confidence="confirmed",
                                cwe="CWE-674",
                                tool=tname, parameter=pname,
                                payload=f"depth={max_nesting_depth}",
                                description=(
                                    f"Sending a {max_nesting_depth}-deep nested "
                                    f"object caused a {dt:.2f}s response or "
                                    "server error. Parser may be vulnerable to "
                                    "stack-overflow / quadratic blowup."
                                ),
                                remediation="Cap JSON nesting at parse time.",
                            ))
                    elif t == "array":
                        big = list(range(max_array_size))
                        args = helpers.fill_defaults(schema)
                        args[pname] = big
                        r = mcp.call_tool_safe(tname, args)
                        rb.add_evidence(evidence.ev_mcp_call(
                            r, note=f"big-array {tname}/{pname} n={max_array_size}"))

            # 4) Extra property
            if test_extras and additional is False:
                args = helpers.fill_defaults(schema)
                args["MINERVA_EXTRA"] = "x"
                r = mcp.call_tool_safe(tname, args)
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"extra-prop {tname}"))
                if r.get("ok") and not r.get("is_error"):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "schema_type_confusion"),
                        title=f"Extra property accepted by '{tname}' (additionalProperties=false)",
                        category="schema_type_confusion",
                        severity="low", confidence="confirmed",
                        cwe="CWE-20",
                        tool=tname,
                        description=(
                            "Schema declares additionalProperties=false but server "
                            "accepted MINERVA_EXTRA. Useful for parameter pollution."
                        ),
                        remediation="Reject unknown keys.",
                        payload="MINERVA_EXTRA=x",
                    ))

            # 5) Required-field omission
            if test_required and required:
                missing = required[0]
                args = helpers.fill_defaults(schema)
                args.pop(missing, None)
                r = mcp.call_tool_safe(tname, args)
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"missing-required {tname}/{missing}"))
                if r.get("ok") and not r.get("is_error"):
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "schema_type_confusion"),
                        title=f"Required field '{missing}' not enforced on '{tname}'",
                        category="schema_type_confusion",
                        severity="medium", confidence="confirmed",
                        cwe="CWE-20",
                        tool=tname, parameter=missing,
                        description=("Schema lists '{}' as required but tool ran "
                                     "successfully without it.").format(missing),
                        remediation="Reject calls missing required fields.",
                    ))

            # 6) oneOf / anyOf confusion
            if test_oneof:
                for pname, pspec in props.items():
                    if not isinstance(pspec, dict):
                        continue
                    branches = pspec.get("oneOf") or pspec.get("anyOf")
                    if not branches or len(branches) < 2:
                        continue
                    # Build a value that satisfies the first two branches
                    polymorph = {"type": "polymorphic", "value": 1, "name": "x"}
                    args = helpers.fill_defaults(schema)
                    args[pname] = polymorph
                    r = mcp.call_tool_safe(tname, args)
                    rb.add_evidence(evidence.ev_mcp_call(
                        r, note=f"oneOf-confusion {tname}/{pname}"))
                    # No strong assertion — just record. A server returning
                    # ok with a polymorphic input is informative.
        return rb.finalize()
    finally:
        mcp.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wrong_type_values(declared_type: str | None):
    """Return (label, value) pairs that violate the declared type."""
    if declared_type == "string":
        return [("integer", 12345), ("array", [1, 2, 3]),
                ("object", {"x": 1}), ("null", None), ("boolean", True)]
    if declared_type in ("integer", "number"):
        return [("string", "12345"), ("array", [1]),
                ("object", {"v": 1}), ("null", None), ("boolean", True)]
    if declared_type == "boolean":
        return [("string", "true"), ("integer", 1),
                ("array", [True]), ("null", None)]
    if declared_type == "array":
        return [("string", "[1,2,3]"), ("object", {"0": 1}), ("null", None)]
    if declared_type == "object":
        return [("string", "{\"x\":1}"), ("array", [{"x": 1}]), ("null", None)]
    # No declared type — try a couple obviously-wrong shapes
    return [("array", [1, 2]), ("object", {"x": 1}), ("integer", 12345)]


def _nested_object(depth: int) -> dict:
    """Build a JSON object with `depth` levels of nesting."""
    out: dict = {"v": 1}
    cur = out
    for _ in range(depth):
        new = {"v": 1}
        cur["nested"] = new
        cur = new
    return out


def _looks_like_crash(r: dict, dt: float) -> bool:
    if r.get("ok") and not r.get("is_error"):
        return False
    err = r.get("error") or {}
    if isinstance(err, dict):
        msg = (err.get("message") or "").lower()
        # Internal errors / unhandled exceptions
        if any(m in msg for m in ("internal error", "unhandled",
                                   "traceback", "panic",
                                   "stack overflow", "recursion",
                                   "maxrecursiondepth", "exception")):
            return True
    status = r.get("status")
    if status and status >= 500:
        return True
    text = (r.get("text_output") or "").lower()
    if any(m in text for m in ("traceback (", "stacktrace", "panic:",
                                "java.lang.", "Exception in thread")):
        return True
    return False
