"""
Structured evidence + finding builders.

Pentest reports are only useful if each finding carries enough forensic
detail to reproduce and defend. Attack scripts import these helpers to
build consistent shapes so the frontend, report engine, and future
ML/LLM analysers can rely on them.

Shape of a Finding
------------------
{
  "id": "uuid",
  "attack_id": str,
  "title": str,
  "severity": "critical|high|medium|low|info",
  "confidence": "confirmed|high|medium|low",
  "category": str,              # e.g. "command_injection"
  "cwe": "CWE-78",
  "cve": str | None,
  "vulnerable": bool,
  "target": {host, port, protocol, base_url, ...},
  "tool": str | None,
  "parameter": str | None,
  "payload": str | None,
  "description": str,
  "impact": str,
  "remediation": str,
  "references": [url, ...],
  "evidence": [ Evidence, ... ],
  "timestamp": iso8601,
  "duration_ms": int,
}

Shape of an Evidence item
-------------------------
{
  "type": "http_request|http_response|mcp_call|oob_hit|screenshot|file|raw",
  "timestamp": iso8601,
  "summary": str,
  "data": {...}              # type-specific payload
}

A ReportBuilder aggregates findings + run-level metadata and returns
the dict that attacks return to the runner.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import uuid
from typing import Any


SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("confirmed", "high", "medium", "low")


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe(value: Any, max_len: int = 8000) -> Any:
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            value = repr(value)
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + f"... [truncated {len(value) - max_len} chars]"
    return value


# ---------------------------------------------------------------------------
# Evidence items
# ---------------------------------------------------------------------------

def ev_mcp_call(mcp_response: dict, *, note: str = "") -> dict:
    """Wrap the structured response of MCPClient methods."""
    req = mcp_response.get("request") or {}
    resp = mcp_response.get("response") or {}
    method = req.get("method", "?")
    return {
        "type": "mcp_call",
        "timestamp": _iso_now(),
        "summary": note or f"{method} → {mcp_response.get('status') or 'n/a'}"
                          f" ({mcp_response.get('latency_ms', 0)}ms)",
        "data": {
            "transport": mcp_response.get("transport"),
            "status": mcp_response.get("status"),
            "latency_ms": mcp_response.get("latency_ms"),
            "request": _safe(req),
            "response": _safe(resp),
            "headers": mcp_response.get("headers"),
            "error": mcp_response.get("error"),
        },
    }


def ev_http(req: dict, resp: dict, *, note: str = "") -> dict:
    return {
        "type": "http_request",
        "timestamp": _iso_now(),
        "summary": note or f"{req.get('method','GET')} {req.get('url','?')} "
                           f"→ {resp.get('status','?')}",
        "data": {"request": _safe(req), "response": _safe(resp)},
    }


def ev_oob_hit(token: str, hits: list[dict], *, note: str = "") -> dict:
    return {
        "type": "oob_hit",
        "timestamp": _iso_now(),
        "summary": note or f"{len(hits)} out-of-band callback(s) on {token[:12]}",
        "data": {"token": token, "hits": hits},
    }


def ev_raw(summary: str, data: Any) -> dict:
    return {
        "type": "raw",
        "timestamp": _iso_now(),
        "summary": summary,
        "data": _safe(data),
    }


def ev_file(path: str, content: str | bytes, *, note: str = "") -> dict:
    if isinstance(content, bytes):
        content_str = content[:4096].decode("utf-8", errors="replace")
    else:
        content_str = str(content)[:4096]
    digest = hashlib.sha256(
        content if isinstance(content, bytes) else content.encode("utf-8", "replace")
    ).hexdigest()
    return {
        "type": "file",
        "timestamp": _iso_now(),
        "summary": note or f"{path} ({len(content_str)}B)",
        "data": {"path": path, "sha256": digest, "excerpt": content_str},
    }


# ---------------------------------------------------------------------------
# Finding / ReportBuilder
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, *,
                 attack_id: str,
                 title: str,
                 category: str,
                 severity: str = "medium",
                 confidence: str = "medium",
                 vulnerable: bool = True,
                 target: dict | None = None,
                 tool: str | None = None,
                 parameter: str | None = None,
                 payload: str | None = None,
                 description: str = "",
                 impact: str = "",
                 remediation: str = "",
                 cwe: str | None = None,
                 cve: str | None = None,
                 references: list | None = None,
                 evidence: list | None = None,
                 duration_ms: int | None = None):
        sev = severity.lower()
        conf = confidence.lower()
        if sev not in SEVERITIES:
            sev = "medium"
        if conf not in CONFIDENCES:
            conf = "medium"
        self.data = {
            "id": uuid.uuid4().hex,
            "attack_id": attack_id,
            "title": title,
            "severity": sev,
            "confidence": conf,
            "category": category,
            "vulnerable": bool(vulnerable),
            "target": target or {},
            "tool": tool,
            "parameter": parameter,
            "payload": payload,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "cwe": cwe,
            "cve": cve,
            "references": references or [],
            "evidence": evidence or [],
            "timestamp": _iso_now(),
            "duration_ms": duration_ms,
        }

    def add_evidence(self, item: dict) -> "Finding":
        self.data["evidence"].append(item)
        return self

    def to_dict(self) -> dict:
        return dict(self.data)


class ReportBuilder:
    """Collects findings + logs across an attack run."""

    def __init__(self, attack_id: str, target: dict):
        self._attack_id = attack_id
        self._target = target
        self._start = _iso_now()
        self._start_ts = _dt.datetime.now(_dt.timezone.utc)
        self._findings: list[dict] = []
        self._logs: list[str] = []
        self._extra_evidence: list[dict] = []
        self._run_id = uuid.uuid4().hex[:12]

    # Logging ----------------------------------------------------------------
    def log(self, msg: str) -> None:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%H:%M:%S")
        self._logs.append(f"[{ts}] {msg}")

    def info(self, msg: str) -> None:
        self.log(f"[INFO]  {msg}")

    def warn(self, msg: str) -> None:
        self.log(f"[WARN]  {msg}")

    def error(self, msg: str) -> None:
        self.log(f"[ERROR] {msg}")

    def success(self, msg: str) -> None:
        self.log(f"[+] {msg}")

    # Findings ---------------------------------------------------------------
    def add_finding(self, finding: Finding | dict) -> None:
        d = finding.to_dict() if isinstance(finding, Finding) else dict(finding)
        d.setdefault("attack_id", self._attack_id)
        d.setdefault("target", self._target)
        self._findings.append(d)
        conf = d.get("confidence", "?")
        sev = d.get("severity", "?")
        self.success(f"[{sev.upper()}] [{conf.upper()}] {d.get('title', '?')}")

    def add_evidence(self, item: dict) -> None:
        self._extra_evidence.append(item)

    # Result -----------------------------------------------------------------
    def finalize(self, *, success: bool | None = None) -> dict:
        end_ts = _dt.datetime.now(_dt.timezone.utc)
        duration_ms = int((end_ts - self._start_ts).total_seconds() * 1000)
        if success is None:
            success = True
        counts = {
            "critical": sum(1 for f in self._findings if f["severity"] == "critical"),
            "high":     sum(1 for f in self._findings if f["severity"] == "high"),
            "medium":   sum(1 for f in self._findings if f["severity"] == "medium"),
            "low":      sum(1 for f in self._findings if f["severity"] == "low"),
            "info":     sum(1 for f in self._findings if f["severity"] == "info"),
            "confirmed": sum(1 for f in self._findings if f["confidence"] == "confirmed"),
        }
        return {
            "success": success,
            "findings": self._findings,
            "evidence": self._extra_evidence,
            "logs": self._logs,
            "summary": {
                "run_id": self._run_id,
                "attack_id": self._attack_id,
                "target": self._target,
                "started_at": self._start,
                "completed_at": _iso_now(),
                "duration_ms": duration_ms,
                "total_findings": len(self._findings),
                "counts": counts,
            },
        }


__all__ = [
    "Finding", "ReportBuilder",
    "ev_mcp_call", "ev_http", "ev_oob_hit", "ev_raw", "ev_file",
    "SEVERITIES", "CONFIDENCES",
]
