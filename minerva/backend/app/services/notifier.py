"""
Minerva notifier — webhook + Slack integrations.

Fires when a finding lands at or above a configured severity threshold
during campaign execution. Configurable per-user via SystemSettings
(key prefix ``notifier.``) or via environment variables.

Env vars honoured (global defaults):
    MINERVA_WEBHOOK_URL      generic POST JSON
    MINERVA_SLACK_WEBHOOK    Slack incoming-webhook URL
    MINERVA_NOTIFY_MIN       critical|high|medium|low  (default high)

Usage from attack runner / campaign runner::

    from app.services import notifier
    notifier.notify_finding(finding, target=target, campaign_name=...)

All deliveries happen in a background thread so the hot path never
blocks on a slow webhook.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from typing import Any

import requests


_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _min_sev_default() -> int:
    s = (os.environ.get("MINERVA_NOTIFY_MIN") or "high").lower()
    return _SEV_RANK.get(s, 4)


def _engagement_endpoints(engagement_id: str | None) -> dict:
    """Per-engagement webhook config. Falls back to system / env."""
    if not engagement_id:
        return _global_endpoints()
    try:
        from app.models import Engagement
        eng = Engagement.query.get(engagement_id)
        if not eng:
            return _global_endpoints()
        return {
            "webhook_url": eng.webhook_url or "",
            "webhook_secret": eng.webhook_secret or "",
            "slack_url": eng.slack_url or "",
            "teams_url": eng.teams_url or "",
            "min_sev": _SEV_RANK.get(
                (eng.notify_min_severity or "high").lower(), 4),
            "engagement_name": eng.name,
        }
    except Exception:
        return _global_endpoints()


def _global_endpoints() -> dict:
    out: dict[str, Any] = {}
    try:
        from app.models import SystemSettings
        for key in ("notifier.webhook_url", "notifier.webhook_secret",
                    "notifier.slack_url", "notifier.teams_url"):
            row = SystemSettings.query.filter_by(key=key).first()
            if row and row.value:
                out[key.rsplit(".", 1)[1]] = row.value
    except Exception:
        pass
    out.setdefault("webhook_url", os.environ.get("MINERVA_WEBHOOK_URL", ""))
    out.setdefault("slack_url", os.environ.get("MINERVA_SLACK_WEBHOOK", ""))
    out.setdefault("teams_url", os.environ.get("MINERVA_TEAMS_WEBHOOK", ""))
    out.setdefault("webhook_secret", os.environ.get("MINERVA_WEBHOOK_SECRET", ""))
    out.setdefault("min_sev", _min_sev_default())
    out.setdefault("engagement_name", None)
    return out


def _sign(body: bytes, secret: str) -> str:
    """HMAC-SHA256 signature for outbound webhooks."""
    if not secret:
        return ""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _post(url: str, payload: dict | str, *, is_form: bool = False,
          timeout: float = 6.0, secret: str | None = None,
          extra_headers: dict | None = None) -> None:
    try:
        headers = {"User-Agent": "Minerva-Notifier/1.0"}
        if extra_headers:
            headers.update(extra_headers)
        if is_form:
            requests.post(url, data=payload, timeout=timeout, headers=headers)
        else:
            body = json.dumps(payload, default=str).encode("utf-8")
            if secret:
                headers["X-Minerva-Signature"] = _sign(body, secret)
                headers["Content-Type"] = "application/json"
            requests.post(url, data=body if secret else None,
                          json=None if secret else payload,
                          timeout=timeout, headers=headers)
    except Exception:
        pass  # never raise into caller


def notify_finding(finding: dict, *, target: dict | None = None,
                   campaign_name: str | None = None,
                   engagement_id: str | None = None) -> None:
    """Fire notifications for a single finding if severity passes the
    configured minimum. Non-blocking."""
    try:
        sev = str(finding.get("severity") or "info").lower()
    except Exception:
        return

    eng_id = engagement_id or finding.get("engagement_id")
    endpoints = _engagement_endpoints(eng_id)
    if _SEV_RANK.get(sev, 0) < endpoints.get("min_sev", 4):
        return
    if not (endpoints.get("webhook_url") or endpoints.get("slack_url")
            or endpoints.get("teams_url")):
        return

    summary = {
        "event": "finding",
        "title": finding.get("title"),
        "severity": sev,
        "confidence": finding.get("confidence"),
        "category": finding.get("category"),
        "tool": finding.get("tool"),
        "parameter": finding.get("parameter"),
        "target": target or finding.get("target"),
        "cwe": finding.get("cwe"),
        "cvss_v31_vector": finding.get("cvss_v31_vector") or finding.get("cvss_vector"),
        "cvss_v40_vector": finding.get("cvss_v40_vector"),
        "cvss_score": finding.get("cvss_score"),
        "campaign": campaign_name,
        "engagement": endpoints.get("engagement_name"),
        "engagement_id": eng_id,
        "dedup_key": finding.get("dedup_key"),
    }

    if endpoints.get("webhook_url"):
        threading.Thread(
            target=_post,
            args=(endpoints["webhook_url"], summary),
            kwargs={"secret": endpoints.get("webhook_secret")},
            daemon=True).start()

    if endpoints.get("slack_url"):
        threading.Thread(
            target=_post,
            args=(endpoints["slack_url"], _to_slack(summary)),
            daemon=True).start()

    if endpoints.get("teams_url"):
        threading.Thread(
            target=_post,
            args=(endpoints["teams_url"], _to_teams(summary)),
            daemon=True).start()


def notify_campaign_complete(campaign_name: str, stats: dict,
                             *, engagement_id: str | None = None) -> None:
    """Summary ping at end of a campaign."""
    endpoints = _engagement_endpoints(engagement_id)
    payload = {"event": "campaign_complete",
               "campaign": campaign_name, "stats": stats,
               "engagement": endpoints.get("engagement_name"),
               "engagement_id": engagement_id}
    if endpoints.get("webhook_url"):
        threading.Thread(
            target=_post,
            args=(endpoints["webhook_url"], payload),
            kwargs={"secret": endpoints.get("webhook_secret")},
            daemon=True).start()
    if endpoints.get("slack_url"):
        threading.Thread(
            target=_post,
            args=(endpoints["slack_url"], {
                "text": (f":white_check_mark: Campaign *{campaign_name}* "
                         f"complete — grade {stats.get('grade','?')}, "
                         f"{stats.get('total_findings',0)} findings "
                         f"({stats.get('critical',0)} critical, "
                         f"{stats.get('high',0)} high)."),
            }), daemon=True).start()
    if endpoints.get("teams_url"):
        threading.Thread(
            target=_post,
            args=(endpoints["teams_url"],
                  _to_teams_summary(campaign_name, stats)),
            daemon=True).start()


def _to_teams(summary: dict) -> dict:
    """MS Teams Adaptive Card payload."""
    sev = summary["severity"]
    color = {"critical": "attention", "high": "attention",
             "medium": "warning", "low": "good", "info": "default"}.get(sev, "default")
    tgt = summary.get("target") or {}
    tgt_str = (tgt.get("base_url") or
               f"{tgt.get('host','?')}:{tgt.get('port','?')}")
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "color": color,
                     "text": f"{sev.upper()}: {summary.get('title')}"},
                    {"type": "FactSet", "facts": [
                        {"title": "Category", "value": summary.get("category") or "—"},
                        {"title": "Confidence", "value": summary.get("confidence") or "—"},
                        {"title": "Tool", "value": summary.get("tool") or "—"},
                        {"title": "Target", "value": tgt_str},
                        {"title": "CWE", "value": summary.get("cwe") or "—"},
                        {"title": "Engagement", "value": summary.get("engagement") or "—"},
                    ]},
                ],
            },
        }],
    }


def _to_teams_summary(campaign: str, stats: dict) -> dict:
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "text": f"Campaign complete: {campaign}"},
                    {"type": "FactSet", "facts": [
                        {"title": "Grade", "value": str(stats.get("grade", "?"))},
                        {"title": "Total findings",
                         "value": str(stats.get("total_findings", 0))},
                        {"title": "Critical",
                         "value": str(stats.get("critical", 0))},
                        {"title": "High", "value": str(stats.get("high", 0))},
                    ]},
                ],
            },
        }],
    }


def _to_slack(summary: dict) -> dict:
    sev = summary["severity"]
    icon = {"critical": ":fire:", "high": ":rotating_light:",
            "medium": ":warning:", "low": ":mag:", "info": ":information_source:"}.get(sev, ":bell:")
    tgt = summary.get("target") or {}
    tgt_str = (tgt.get("base_url") or
               f"{tgt.get('host','?')}:{tgt.get('port','?')}")
    return {
        "text": f"{icon} *{sev.upper()}* — {summary['title']}",
        "blocks": [
            {"type": "header",
             "text": {"type": "plain_text",
                      "text": f"{icon} {sev.upper()}: {summary['title']}"}},
            {"type": "section",
             "fields": [
                 {"type": "mrkdwn", "text": f"*Category:*\n{summary.get('category')}"},
                 {"type": "mrkdwn", "text": f"*Confidence:*\n{summary.get('confidence')}"},
                 {"type": "mrkdwn", "text": f"*CVSS:*\n{summary.get('cvss_score')}"},
                 {"type": "mrkdwn", "text": f"*CWE:*\n{summary.get('cwe') or '—'}"},
                 {"type": "mrkdwn", "text": f"*Tool:*\n{summary.get('tool') or '—'}"},
                 {"type": "mrkdwn", "text": f"*Target:*\n{tgt_str}"},
             ]},
        ],
    }


__all__ = ["notify_finding", "notify_campaign_complete"]
