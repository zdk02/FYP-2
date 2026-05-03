"""
Reports API — builds professional pentest reports from campaign
results using the Minerva report_engine (HTML / PDF / JSON / SARIF).
"""

from __future__ import annotations

import io
import json

from flask import request, jsonify, Response, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.api import api_bp
from app import db
from app.models import (Report, Campaign, AttackExecution, Target, Attack,
                        User, AuditLog)
from app.services import report_engine


def _audit(user_id, action, resource_id, details=None):
    db.session.add(AuditLog(
        user_id=user_id, action=action, resource_type="report",
        resource_id=resource_id,
        details=json.dumps(details) if details else None,
        ip_address=request.remote_addr,
        user_agent=(request.headers.get("User-Agent") or "")[:500],
    ))


def _serialize_report(r: Report) -> dict:
    try:
        content = json.loads(r.content) if r.content else {}
    except Exception:
        content = {}
    campaign = Campaign.query.get(r.campaign_id) if r.campaign_id else None
    return {
        "id": r.id,
        "name": r.name,
        "report_type": r.report_type,
        "format": r.format,
        "campaign": {"id": campaign.id, "name": campaign.name}
        if campaign else None,
        "total_attacks": r.total_attacks or 0,
        "successful_attacks": r.successful_attacks or 0,
        "critical_findings": r.critical_findings or 0,
        "high_findings": r.high_findings or 0,
        "medium_findings": r.medium_findings or 0,
        "low_findings": r.low_findings or 0,
        "risk_grade": content.get("risk", {}).get("grade"),
        "risk_score": content.get("risk", {}).get("score"),
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "generated_by": r.generated_by,
    }


def _build_from_campaign(campaign: Campaign, options: dict) -> dict:
    """Run the report_engine over all executions tied to a campaign."""
    execs = AttackExecution.query.filter_by(campaign_id=campaign.id).all()

    # Lookup tables for enrichment
    attack_lookup = {}
    attack_ids = {ex.attack_id for ex in execs if ex.attack_id}
    if attack_ids:
        for a in Attack.query.filter(Attack.id.in_(attack_ids)).all():
            attack_lookup[a.id] = {
                "name": a.name, "mitre_id": a.mitre_id,
                "attack_type": a.attack_type,
            }

    findings: list[dict] = []
    for ex in execs:
        if not ex.evidence:
            continue
        try:
            ev = json.loads(ex.evidence)
        except Exception:
            continue
        tgt = Target.query.get(ex.target_id) if ex.target_id else None
        attack_meta = attack_lookup.get(ex.attack_id, {})
        for f in (ev.get("findings") or []):
            if isinstance(f, dict):
                if tgt and not f.get("target"):
                    f["target"] = {"name": tgt.name, "host": tgt.host,
                                   "port": tgt.port, "protocol": tgt.protocol,
                                   "base_url": tgt.base_url,
                                   "target_type": tgt.target_type}
                # Enrich with attack metadata so analytics can build MITRE
                # coverage and the UI can show the attack name (not the UUID).
                f.setdefault("attack_id", ex.attack_id)
                f.setdefault("attack_name", attack_meta.get("name"))
                if attack_meta.get("mitre_id") and not f.get("mitre_id"):
                    f["mitre_id"] = attack_meta["mitre_id"]
                if attack_meta.get("attack_type") and not f.get("attack_type"):
                    f["attack_type"] = attack_meta["attack_type"]
                findings.append(f)

    tgt_ids = {ex.target_id for ex in execs if ex.target_id}
    targets = [t.to_dict() for t in
               Target.query.filter(Target.id.in_(tgt_ids)).all()] if tgt_ids else []

    started = min((ex.started_at for ex in execs if ex.started_at),
                  default=None)
    ended = max((ex.completed_at for ex in execs if ex.completed_at),
                default=None)
    return report_engine.build_report(
        title=options.get("title") or f"Pentest Report — {campaign.name}",
        client_name=options.get("client_name", ""),
        assessor=options.get("assessor", "Minerva Framework"),
        targets=targets,
        findings=findings,
        campaign_summary={
            "campaign_id": campaign.id,
            "campaign_name": campaign.name,
            "subtitle": options.get("subtitle"),
            "started_at": started.isoformat() if started else None,
            "completed_at": ended.isoformat() if ended else None,
            "total_executions": len(execs),
        },
        options={"include_evidence": options.get("include_evidence", True),
                 "exec_summary": options.get("exec_summary")},
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@api_bp.route("/reports", methods=["GET"])
@jwt_required()
def list_reports():
    campaign_id = request.args.get("campaign_id")
    q = Report.query
    if campaign_id:
        q = q.filter_by(campaign_id=campaign_id)
    rows = q.order_by(Report.created_at.desc()).all()
    return jsonify({"reports": [_serialize_report(r) for r in rows]}), 200


@api_bp.route("/reports/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id: str):
    r = Report.query.get(report_id)
    if not r:
        return jsonify({"error": "Report not found"}), 404
    base = _serialize_report(r)
    try:
        base["content"] = json.loads(r.content) if r.content else {}
    except Exception:
        base["content"] = {}
    return jsonify(base), 200


@api_bp.route("/reports/generate", methods=["POST"])
@jwt_required()
def generate_report_from_campaign():
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    campaign_id = data.get("campaign_id")
    if not campaign_id:
        return jsonify({"error": "campaign_id required"}), 400
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return jsonify({"error": "Campaign not found"}), 404

    rpt = _build_from_campaign(campaign, data)
    c = rpt["risk"]["severity_counts"]

    row = Report(
        campaign_id=campaign.id,
        name=data.get("name") or rpt["meta"]["title"],
        report_type=data.get("report_type") or "technical",
        format="multi",
        content=json.dumps(rpt, default=str),
        total_attacks=rpt["campaign_summary"].get("total_executions", 0),
        successful_attacks=rpt["risk"]["total_findings"],
        critical_findings=c.get("critical", 0),
        high_findings=c.get("high", 0),
        medium_findings=c.get("medium", 0),
        low_findings=c.get("low", 0),
        recommendations=json.dumps([
            f["remediation"] for f in rpt["findings"]
            if f.get("remediation")
        ][:20]),
        generated_by=user_id,
    )
    db.session.add(row)
    _audit(user_id, "generate", None,
           {"campaign_id": campaign.id,
            "findings_count": rpt["risk"]["total_findings"]})
    db.session.commit()
    return jsonify({"report": _serialize_report(row),
                    "risk": rpt["risk"]}), 201


@api_bp.route("/reports/<report_id>", methods=["PUT"])
@jwt_required()
def update_report(report_id: str):
    """Edit a report's narrative fields.

    Body shape (any subset)::

        {
          "name": "...",
          "executive_summary": "free-text markdown-ish summary",
          "recommendations": ["text 1", "text 2", ...],
          "notes": "free-text appendix / analyst commentary",
          "client_name": "...",
          "assessor": "...",
          "title": "...",
          "findings_overrides": {
              "<finding_id>": {"severity": "high", "notes": "..."}
          }
        }

    The numeric findings + analytics blocks are recomputed when severity
    overrides are present so the charts stay consistent.
    """
    user_id = get_jwt_identity()
    r = Report.query.get(report_id)
    if not r:
        return jsonify({"error": "Report not found"}), 404
    data = request.get_json() or {}

    try:
        content = json.loads(r.content) if r.content else {}
    except Exception:
        content = {}

    changed = []

    if "name" in data:
        new_name = (data["name"] or "").strip()
        if new_name and new_name != r.name:
            r.name = new_name
            content.setdefault("meta", {})["title"] = new_name
            changed.append("name")

    if "title" in data and data["title"]:
        content.setdefault("meta", {})["title"] = str(data["title"])
        changed.append("title")

    if "client_name" in data:
        content.setdefault("meta", {})["client_name"] = str(data["client_name"] or "")
        changed.append("client_name")

    if "assessor" in data:
        content.setdefault("meta", {})["assessor"] = str(data["assessor"] or "")
        changed.append("assessor")

    if "executive_summary" in data:
        content["executive_summary"] = str(data["executive_summary"] or "")
        changed.append("executive_summary")

    if "recommendations" in data:
        recs = data["recommendations"] or []
        if not isinstance(recs, list):
            return jsonify({"error": "recommendations must be a list"}), 400
        recs = [str(x).strip() for x in recs if str(x).strip()]
        content["recommendations_override"] = recs
        r.recommendations = json.dumps(recs[:50])
        changed.append("recommendations")

    if "notes" in data:
        content["notes"] = str(data["notes"] or "")
        changed.append("notes")

    if "findings_overrides" in data and isinstance(data["findings_overrides"], dict):
        overrides = data["findings_overrides"]
        findings = content.get("findings") or []
        valid_sev = {"critical", "high", "medium", "low", "info"}
        touched = 0
        for f in findings:
            ov = overrides.get(f.get("id"))
            if not isinstance(ov, dict):
                continue
            if ov.get("severity") and ov["severity"].lower() in valid_sev:
                f["severity"] = ov["severity"].lower()
                touched += 1
            if "notes" in ov:
                f["analyst_notes"] = str(ov["notes"] or "")
                touched += 1
            if "false_positive" in ov:
                f["false_positive"] = bool(ov["false_positive"])
                touched += 1
        # Recompute analytics so charts reflect new severities
        if touched:
            from collections import Counter
            from app.services import cvss as _cvss
            from app.services.report_engine import _build_analytics
            grade = _cvss.risk_grade(findings)
            content["risk"] = grade
            content["analytics"] = _build_analytics(
                findings, content.get("targets") or [],
                content.get("campaign_summary") or {})
            content["category_counts"] = dict(Counter(
                f.get("category", "unknown") for f in findings))
            sev = grade.get("severity_counts", {})
            r.critical_findings = sev.get("critical", 0)
            r.high_findings = sev.get("high", 0)
            r.medium_findings = sev.get("medium", 0)
            r.low_findings = sev.get("low", 0)
            changed.append(f"findings_overrides({touched})")

    if not changed:
        return jsonify({"message": "No changes"}), 200

    r.content = json.dumps(content, default=str)
    _audit(user_id, "update", report_id, {"changed": changed})
    db.session.commit()

    base = _serialize_report(r)
    base["content"] = content
    return jsonify(base), 200


@api_bp.route("/reports/<report_id>/download", methods=["GET"])
@jwt_required()
def download_report(report_id: str):
    r = Report.query.get(report_id)
    if not r:
        return jsonify({"error": "Report not found"}), 404
    try:
        rpt = json.loads(r.content) if r.content else {}
    except Exception:
        return jsonify({"error": "Report content malformed"}), 500
    fmt = (request.args.get("format") or "html").lower()

    if fmt == "html":
        body = report_engine.render_html(rpt)
        return Response(body, mimetype="text/html",
                        headers={"Content-Disposition":
                                 f'inline; filename="report-{r.id[:8]}.html"'})
    if fmt == "json":
        return Response(report_engine.render_json(rpt),
                        mimetype="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="report-{r.id[:8]}.json"'})
    if fmt == "sarif":
        return Response(report_engine.render_sarif(rpt),
                        mimetype="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="report-{r.id[:8]}.sarif"'})
    if fmt == "pdf":
        body = report_engine.render_pdf(rpt)
        return send_file(io.BytesIO(body), mimetype="application/pdf",
                         as_attachment=True,
                         download_name=f"report-{r.id[:8]}.pdf")
    return jsonify({"error": f"Unsupported format: {fmt}"}), 400


@api_bp.route("/reports/<report_id>", methods=["DELETE"])
@jwt_required()
def delete_report(report_id: str):
    user_id = get_jwt_identity()
    r = Report.query.get(report_id)
    if not r:
        return jsonify({"error": "Report not found"}), 404
    db.session.delete(r)
    _audit(user_id, "delete", report_id)
    db.session.commit()
    return jsonify({"message": "Report deleted"}), 200


@api_bp.route("/reports/preview", methods=["POST"])
@jwt_required()
def preview_report():
    """Render a preview without persisting — handy for UI."""
    data = request.get_json() or {}
    campaign_id = data.get("campaign_id")
    if not campaign_id:
        return jsonify({"error": "campaign_id required"}), 400
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return jsonify({"error": "Campaign not found"}), 404
    rpt = _build_from_campaign(campaign, data)
    fmt = (data.get("format") or "html").lower()
    if fmt == "html":
        return Response(report_engine.render_html(rpt), mimetype="text/html")
    return jsonify(rpt), 200


# ---------------------------------------------------------------------------
# Pro report templates: executive / technical / compliance / diff
# ---------------------------------------------------------------------------

@api_bp.route("/reports/template", methods=["POST"])
@jwt_required()
def render_template():
    """Render one of the four pro templates from a campaign.

    Body: {
      "campaign_id": "...",
      "template": "executive" | "technical" | "compliance" | "diff",
      "framework_key": "owasp_llm_2025",   # for compliance
      "compare_with_campaign_id": "...",    # for diff
      "download": false
    }
    """
    from app.services import report_templates as _tpl
    from app.services import compliance as _comp
    from app.services import cvss as _cvss

    data = request.get_json() or {}
    campaign_id = data.get("campaign_id")
    template = (data.get("template") or "technical").lower()

    if not campaign_id and template != "diff":
        return jsonify({"error": "campaign_id required"}), 400

    campaign = Campaign.query.get(campaign_id) if campaign_id else None
    if campaign_id and not campaign:
        return jsonify({"error": "Campaign not found"}), 404

    if template == "diff":
        a_id = data.get("run_a_id")
        b_id = data.get("run_b_id")
        if not a_id or not b_id:
            return jsonify({"error": "run_a_id and run_b_id required for diff"}), 400
        a = AttackExecution.query.get(a_id)
        b = AttackExecution.query.get(b_id)
        if not a or not b:
            return jsonify({"error": "one or both runs not found"}), 404
        # Reuse the diff_runs logic
        def _findings_from(execution):
            if not execution or not execution.evidence:
                return []
            try:
                d = json.loads(execution.evidence)
            except Exception:
                return []
            if isinstance(d, dict):
                return list(d.get("findings") or [])
            return []
        af = _findings_from(a)
        bf = _findings_from(b)
        a_keys = {f.get("dedup_key"): f for f in af if f.get("dedup_key")}
        b_keys = {f.get("dedup_key"): f for f in bf if f.get("dedup_key")}
        diff = {
            "run_a": {"id": a.id,
                      "started_at": a.started_at.isoformat() if a.started_at else None,
                      "count": len(af)},
            "run_b": {"id": b.id,
                      "started_at": b.started_at.isoformat() if b.started_at else None,
                      "count": len(bf)},
            "new_count": sum(1 for k in b_keys if k not in a_keys),
            "fixed_count": sum(1 for k in a_keys if k not in b_keys),
            "unchanged_count": sum(1 for k in b_keys if k in a_keys
                                   and a_keys[k].get('severity') == b_keys[k].get('severity')),
            "regressed_count": sum(1 for k in b_keys if k in a_keys
                                   and a_keys[k].get('severity') != b_keys[k].get('severity')),
            "new": [b_keys[k] for k in b_keys if k not in a_keys][:200],
            "fixed": [a_keys[k] for k in a_keys if k not in b_keys][:200],
            "regressed": [b_keys[k] for k in b_keys if k in a_keys
                          and a_keys[k].get('severity') != b_keys[k].get('severity')][:200],
        }
        html = _tpl.render_diff(diff, title=data.get("title") or "Diff Report")
        return Response(html, mimetype="text/html")

    # campaign-based templates
    rpt = _build_from_campaign(campaign, data)
    rpt["findings"] = _comp.enrich(_cvss.enrich_with_v4(rpt["findings"]))
    if template == "executive":
        html = _tpl.render_executive(rpt)
    elif template == "compliance":
        html = _tpl.render_compliance(
            rpt, framework_key=data.get("framework_key") or "owasp_llm_2025",
        )
    else:
        html = _tpl.render_technical(rpt)

    if data.get("download"):
        body = html.encode("utf-8")
        return send_file(io.BytesIO(body), mimetype="text/html",
                         as_attachment=True,
                         download_name=f"minerva-{template}-{campaign.id[:8]}.html")
    return Response(html, mimetype="text/html")
