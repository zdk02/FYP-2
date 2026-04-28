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

import json
import os
import threading
from typing import Any

import requests


_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _min_sev() -> int:
    s = (os.environ.get("MINERVA_NOTIFY_MIN") or "high").lower()
    return _SEV_RANK.get(s, 4)


def _endpoints() -> dict[str, str]:
    # Settings table takes precedence; env as fallback.
    out: dict[str, str] = {}
    try:
        from app.models import SystemSettings
        for key in ("notifier.webhook_url", "notifier.slack_url"):
            row = SystemSettings.query.filter_by(key=key).first()
            if row and row.value:
                out[key.rsplit(".", 1)[1]] = row.value
    except Exception:
        pass
    out.setdefault("webhook_url", os.environ.get("MINERVA_WEBHOOK_URL", ""))
    out.setdefault("slack_url",
                   os.environ.get("MINERVA_SLACK_WEBHOOK", ""))
    return out


def _post(url: str, payload: dict | str, *, is_form: bool = False,
          timeout: float = 6.0) -> None:
    try:
        if is_form:
            requests.post(url, data=payload, timeout=timeout)
        else:
            requests.post(url, json=payload, timeout=timeout)
    except Exception:
        pass  # never raise into caller


def notify_finding(finding: dict, *, target: dict | None = None,
                   campaign_name: str | None = None) -> None:
    """Fire notifications for a single finding if severity passes the
    configured minimum. Non-blocking."""
    try:
        sev = str(finding.get("severity") or "info").lower()
        if _SEV_RANK.get(sev, 0) < _min_sev():
            return
    except Exception:
        return

    endpoints = _endpoints()
    if not endpoints.get("webhook_url") and not endpoints.get("slack_url"):
        return

    summary = {
        "title": finding.get("title"),
        "severity": sev,
        "confidence": finding.get("confidence"),
        "category": finding.get("category"),
        "tool": finding.get("tool"),
        "parameter": finding.get("parameter"),
        "target": target or finding.get("target"),
        "cwe": finding.get("cwe"),
        "cvss_score": finding.get("cvss_score"),
        "campaign": campaign_name,
    }

    # Webhook (generic JSON)
    if endpoints.get("webhook_url"):
        threading.Thread(
            target=_post, args=(endpoints["webhook_url"], summary),
            daemon=True).start()

    # Slack (incoming-webhook format)
    if endpoints.get("slack_url"):
        threading.Thread(
            target=_post,
            args=(endpoints["slack_url"], _to_slack(summary)),
            daemon=True).start()


def notify_campaign_complete(campaign_name: str, stats: dict) -> None:
    """Summary ping at end of a campaign."""
    endpoints = _endpoints()
    payload = {"event": "campaign_complete",
               "campaign": campaign_name, "stats": stats}
    if endpoints.get("webhook_url"):
        threading.Thread(target=_post,
                         args=(endpoints["webhook_url"], payload),
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
