"""
SARIF 2.1.0 export endpoints.

Two entry-points:
  - POST /reports/sarif       — bundle ad-hoc list of findings into SARIF
  - GET  /campaigns/:id/sarif — emit SARIF for all findings in a campaign
"""

from __future__ import annotations

import io
import json

from flask import Response, jsonify, request, send_file
from flask_jwt_extended import jwt_required

from app import db
from app.api import api_bp
from app.models import AttackExecution, Campaign, Engagement
from app.services import compliance, cvss, sarif_exporter


def _findings_from_campaign(campaign: Campaign) -> list[dict]:
    execs = AttackExecution.query.filter_by(campaign_id=campaign.id).all()
    out = []
    for ex in execs:
        if not ex.evidence:
            continue
        try:
            parsed = json.loads(ex.evidence)
        except Exception:
            continue
        if isinstance(parsed, dict):
            for f in parsed.get("findings") or []:
                out.append(f)
        elif isinstance(parsed, list):
            for f in parsed:
                if isinstance(f, dict):
                    out.append(f)
    return out


def _enrich(findings: list[dict]) -> list[dict]:
    out = cvss.enrich_with_v4(findings)
    out = compliance.enrich(out)
    return out


def _build_compliance_lookup(findings: list[dict]) -> dict:
    seen = set()
    lookup = {}
    for f in findings:
        cat = (f.get("category") or "").lower()
        if cat and cat not in seen:
            seen.add(cat)
            cm = compliance.for_category(cat)
            if cm:
                lookup[cat] = cm
    return lookup


@api_bp.route("/reports/sarif", methods=["POST"])
@jwt_required()
def emit_sarif_from_findings():
    data = request.get_json() or {}
    findings = data.get("findings") or []
    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list"}), 400
    enriched = _enrich(findings)
    lookup = _build_compliance_lookup(enriched)
    sarif = sarif_exporter.build_sarif(
        enriched,
        run_metadata=data.get("run_metadata") or {},
        compliance_lookup=lookup,
    )
    if data.get("download"):
        buf = io.BytesIO(json.dumps(sarif, indent=2).encode("utf-8"))
        return send_file(buf, mimetype="application/sarif+json",
                         as_attachment=True,
                         download_name="minerva-findings.sarif")
    return Response(json.dumps(sarif, indent=2),
                    mimetype="application/sarif+json")


@api_bp.route("/campaigns/<campaign_id>/sarif", methods=["GET"])
@jwt_required()
def emit_sarif_for_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return jsonify({"error": "campaign not found"}), 404
    findings = _findings_from_campaign(campaign)
    enriched = _enrich(findings)
    lookup = _build_compliance_lookup(enriched)
    eng = (Engagement.query.get(campaign.engagement_id)
           if getattr(campaign, "engagement_id", None) else None)
    sarif = sarif_exporter.build_sarif(
        enriched,
        run_metadata={
            "campaign_id": campaign.id,
            "campaign_name": campaign.name,
            "engagement": eng.name if eng else None,
            "engagement_id": eng.id if eng else None,
        },
        compliance_lookup=lookup,
    )
    download = (request.args.get("download", "false").lower() == "true")
    if download:
        buf = io.BytesIO(json.dumps(sarif, indent=2).encode("utf-8"))
        return send_file(buf, mimetype="application/sarif+json",
                         as_attachment=True,
                         download_name=f"{campaign.name.replace(' ', '_')}.sarif")
    return Response(json.dumps(sarif, indent=2),
                    mimetype="application/sarif+json")
