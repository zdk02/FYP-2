"""
MCP Credential Theft — harvests credentials that leak via tool responses
and resources. Narrower than Information Disclosure (Pro): ONLY credential
classes, with precise patterns and classification.
"""

import re as _re


_CRED_PATTERNS = [
    (r"sk-[A-Za-z0-9]{20,}",                       "openai_api_key"),
    (r"sk-ant-[A-Za-z0-9_-]{20,}",                 "anthropic_api_key"),
    (r"xox[pbar]-[A-Za-z0-9-]+",                   "slack_token"),
    (r"ghp_[A-Za-z0-9]{20,}",                      "github_pat"),
    (r"gho_[A-Za-z0-9]{20,}",                      "github_oauth"),
    (r"AKIA[0-9A-Z]{16}",                          "aws_access_key"),
    (r"(?i)aws_secret[^=]*=\s*['\"]?([A-Za-z0-9/+]{40})['\"]?",
                                                    "aws_secret_key"),
    (r"AIza[0-9A-Za-z_-]{35}",                     "google_api_key"),
    (r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----", "private_key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt"),
    (r"postgres(?:ql)?://[^:/\s]+:[^@/\s]+@",      "postgres_dsn"),
    (r"mysql://[^:/\s]+:[^@/\s]+@",                "mysql_dsn"),
    (r"mongodb(?:\+srv)?://[^:/\s]+:[^@/\s]+@",    "mongo_dsn"),
    (r"Bearer\s+[A-Za-z0-9_.-]{20,}",              "bearer_token"),
]


def execute(target, params, context):
    rb = evidence.ReportBuilder(context.get("attack_id", "cred_theft"), target)
    timeout = int(params.get("timeout", 25))

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

        # Scan every resource
        for res in disc.get("resources") or []:
            uri = res.get("uri")
            if not uri: continue
            r = mcp.resources_read(uri)
            if not r.get("ok"): continue
            for c in (r.get("result") or {}).get("contents") or []:
                _scan(c.get("text") or "", f"resource:{uri}", rb, context)

        # Scan every tool's default-call response
        for t in disc.get("tools") or []:
            name = t.get("name")
            if not name: continue
            args = helpers.fill_defaults(t.get("inputSchema") or {})
            r = mcp.call_tool_safe(name, args)
            rb.add_evidence(evidence.ev_mcp_call(r, note=f"cred-scan {name}"))
            _scan(r.get("text_output") or "", f"tool:{name}", rb, context)
        return rb.finalize()
    finally:
        mcp.close()


def _scan(text: str, source: str, rb, context):
    for pat, label in _CRED_PATTERNS:
        m = _re.search(pat, text)
        if not m: continue
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "cred_theft"),
            title=f"{label.replace('_',' ').title()} leaked in {source}",
            category="credential_theft", severity="critical",
            confidence="high", cwe="CWE-532",
            description=(
                f"Response from {source} contained a string matching {label}. "
                "Any client/LLM reading this output has the credentials in its "
                "context window."
            ),
            impact=(
                "Credential disclosure. Depending on scope: account takeover, "
                "data exfil, cloud pivot, lateral compromise."
            ),
            remediation=(
                "Never return raw credentials. Replace with opaque handles "
                "resolved server-side. Add DLP patterns at the egress layer "
                "to redact before shipping responses out."
            ),
            payload=m.group(0)[:80],
        ))
        return  # one per source is enough
