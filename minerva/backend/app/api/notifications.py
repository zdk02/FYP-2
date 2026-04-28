"""
Notifier config API. Stores webhook + Slack URLs in SystemSettings.
"""

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from app.api import api_bp
from app.api.users import admin_required
from app import db
from app.models import SystemSettings
from app.services import notifier


_KEYS = ("notifier.webhook_url", "notifier.slack_url", "notifier.min_severity")


def _get(key, default=""):
    row = SystemSettings.query.filter_by(key=key).first()
    return row.value if row and row.value else default


def _set(key, value, desc):
    row = SystemSettings.query.filter_by(key=key).first()
    if row is None:
        db.session.add(SystemSettings(key=key, value=value, value_type="string",
                                       description=desc, is_editable=True))
    else:
        row.value = value


@api_bp.route("/notifications/config", methods=["GET"])
@jwt_required()
def get_notif_config():
    return jsonify({
        "webhook_url": _get("notifier.webhook_url"),
        "slack_url": _get("notifier.slack_url"),
        "min_severity": _get("notifier.min_severity", "high"),
    })


@api_bp.route("/notifications/config", methods=["PUT"])
@admin_required
def put_notif_config():
    body = request.get_json() or {}
    _set("notifier.webhook_url", body.get("webhook_url", ""),
         "Generic POST webhook for findings")
    _set("notifier.slack_url", body.get("slack_url", ""),
         "Slack incoming-webhook URL")
    _set("notifier.min_severity", body.get("min_severity", "high"),
         "Minimum severity to notify about")
    db.session.commit()
    return jsonify({"message": "Notifier config saved"}), 200


@api_bp.route("/notifications/test", methods=["POST"])
@admin_required
def test_notify():
    fake = {
        "title": "Minerva test notification",
        "severity": "critical", "confidence": "confirmed",
        "category": "rce", "tool": "test_tool", "parameter": "x",
        "cwe": "CWE-94", "cvss_score": 10.0,
    }
    notifier.notify_finding(fake, target={"base_url": "https://example.com"},
                            campaign_name="test-campaign")
    return jsonify({"message": "Test dispatched (fire-and-forget)"}), 200
