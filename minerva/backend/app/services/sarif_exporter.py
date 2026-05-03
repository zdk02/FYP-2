"""
SARIF 2.1.0 exporter.

SARIF (Static Analysis Results Interchange Format) is the lingua franca
modern security tooling emits — required by GitHub Advanced Security,
GitLab, Azure DevOps, and most SIEMs that ingest scan results.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

Minerva findings → SARIF mapping
--------------------------------
- Each unique attack_id (or category) becomes a `rule` in `tool.driver.rules`.
- Each finding becomes a `result` referencing the rule by its index.
- target.base_url is recorded as `locations[*].physicalLocation.artifactLocation.uri`.
- evidence items are attached as `attachments`.
- CVSS vectors and CWE go into `properties` (SARIF Result property bag).
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"


_LEVEL_BY_SEV = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _truncate(s: Any, n: int = 4000) -> str:
    if not isinstance(s, str):
        s = json.dumps(s, default=str) if not isinstance(s, (int, float, bool)) else str(s)
    return s if len(s) <= n else s[:n] + f"... [truncated {len(s) - n} chars]"


def build_sarif(findings: list[dict], *,
                tool_name: str = "Minerva",
                tool_version: str = "1.0.0",
                informational_uri: str = "https://github.com/anthropics/minerva",
                run_metadata: dict | None = None,
                compliance_lookup: dict | None = None) -> dict:
    """Build a SARIF 2.1.0 document from a list of Minerva findings.

    `compliance_lookup` is a dict mapping attack_id (or category) → list of
    compliance frameworks (OWASP LLM Top-10, MITRE ATLAS, etc.); if
    provided, those go into the result property bag.
    """
    rules_by_id: dict[str, dict] = {}
    rule_index_by_id: dict[str, int] = {}
    results: list[dict] = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        rule_id = (str(f.get("category") or f.get("attack_id") or "minerva.generic")
                   .strip().lower().replace(" ", "_"))
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _build_rule(rule_id, f, compliance_lookup)
            rule_index_by_id[rule_id] = len(rules_by_id) - 1
        results.append(_build_result(rule_id, rule_index_by_id[rule_id], f))

    rules = list(rules_by_id.values())

    invocation = {
        "executionSuccessful": True,
        "endTimeUtc": _now_iso(),
    }
    if run_metadata:
        invocation["properties"] = run_metadata

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": informational_uri,
                        "rules": rules,
                        "semanticVersion": tool_version,
                    },
                },
                "invocations": [invocation],
                "results": results,
                "columnKind": "utf16CodeUnits",
            },
        ],
    }
    return sarif


def _build_rule(rule_id: str, sample_finding: dict,
                compliance_lookup: dict | None) -> dict:
    """Build a SARIF rule entry from one finding (used as exemplar)."""
    title = sample_finding.get("title") or rule_id.replace("_", " ").title()
    description = sample_finding.get("description") or ""
    cwe = sample_finding.get("cwe")
    refs = sample_finding.get("references") or []

    properties = {
        "category": sample_finding.get("category"),
        "tags": ["security", "mcp"],
    }
    if cwe:
        properties["cwe"] = cwe
        properties["tags"].append(cwe)
    if compliance_lookup:
        cl = compliance_lookup.get(rule_id) or {}
        if cl:
            properties["compliance"] = cl

    rule = {
        "id": rule_id,
        "name": title[:200],
        "shortDescription": {"text": title[:300]},
        "fullDescription": {"text": _truncate(description, 1500)},
        "helpUri": refs[0] if refs else "https://modelcontextprotocol.io/",
        "help": {
            "text": _truncate(
                (sample_finding.get("remediation") or "") + "\n\n"
                + ("References:\n" + "\n".join(refs) if refs else ""),
                3000,
            ),
        },
        "defaultConfiguration": {
            "level": _LEVEL_BY_SEV.get(
                str(sample_finding.get("severity", "medium")).lower(),
                "warning",
            ),
        },
        "properties": properties,
    }
    return rule


def _build_result(rule_id: str, rule_index: int, finding: dict) -> dict:
    severity = str(finding.get("severity", "medium")).lower()
    confidence = str(finding.get("confidence", "")).lower()
    target = finding.get("target") or {}
    artifact_uri = (target.get("base_url")
                    or f"{target.get('protocol', 'mcp')}://"
                       f"{target.get('host', '?')}:{target.get('port', '?')}")

    msg = (finding.get("description") or finding.get("title")
           or "Minerva detected a vulnerability")

    properties = {
        "minerva_finding_id": finding.get("id"),
        "minerva_attack_id": finding.get("attack_id"),
        "minerva_engagement_id": finding.get("engagement_id"),
        "minerva_dedup_key": finding.get("dedup_key"),
        "minerva_severity": severity,
        "minerva_confidence": confidence,
        "minerva_tool": finding.get("tool"),
        "minerva_parameter": finding.get("parameter"),
        "minerva_payload": _truncate(finding.get("payload"), 2000),
        "minerva_impact": _truncate(finding.get("impact"), 2000),
        "minerva_remediation": _truncate(finding.get("remediation"), 2000),
        "minerva_cvss_v31_vector": finding.get("cvss_v31_vector") or finding.get("cvss_vector"),
        "minerva_cvss_v31_score": finding.get("cvss_v31_score") or finding.get("cvss_score"),
        "minerva_cvss_v40_vector": finding.get("cvss_v40_vector"),
        "minerva_cvss_v40_score": finding.get("cvss_v40_score"),
        "minerva_cwe": finding.get("cwe"),
        "minerva_compliance": finding.get("compliance_map"),
        "tags": ["minerva", "mcp", severity, confidence].count(None) and []
                or [t for t in ["minerva", "mcp", severity, confidence] if t],
    }

    attachments = []
    for ev in (finding.get("evidence") or [])[:10]:
        if not isinstance(ev, dict):
            continue
        attachments.append({
            "description": {"text": ev.get("summary", ev.get("type", "evidence"))[:1000]},
            "artifactLocation": {"uri": artifact_uri},
            "regions": [{"snippet": {"text": _truncate(ev.get("data"), 4000)}}],
        })

    result = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL_BY_SEV.get(severity, "warning"),
        "message": {"text": _truncate(msg, 4000)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
                "region": {"startLine": 1},
            },
            "logicalLocations": [{
                "name": finding.get("tool") or rule_id,
                "kind": "tool",
            }],
        }],
        "fingerprints": {
            "primary": finding.get("dedup_key") or finding.get("id") or "unknown",
        },
        "properties": properties,
    }
    if attachments:
        result["attachments"] = attachments
    return result


def export_to_string(findings: list[dict], **kwargs) -> str:
    """Convenience wrapper: returns the SARIF as a JSON string."""
    return json.dumps(build_sarif(findings, **kwargs), indent=2)


__all__ = ["build_sarif", "export_to_string"]
