"""
Replay API — re-run a single payload from a finding.

Operators need a one-click "reproduce" path so they can verify a fix or
confirm reproducibility for the report. Replay is engagement-scoped:
the original engagement_id is reused so the preflight gate runs again
(scope hasn't changed since the finding was discovered? we double-check).
"""

from __future__ import annotations

import json

from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from app.api import api_bp
from app.models import AttackExecution, Attack, Target
from app.services import attack_runner, audit_service


def _find_in_evidence_blob(parsed, finding_id: str) -> dict | None:
    if isinstance(parsed, dict):
        for f in (parsed.get("findings") or []):
            if f.get("id") == finding_id:
                return f
    elif isinstance(parsed, list):
        for f in parsed:
            if isinstance(f, dict) and f.get("id") == finding_id:
                return f
    return None


@api_bp.route("/executions/<execution_id>/replay", methods=["POST"])
@jwt_required()
def replay_finding(execution_id):
    """Replay a single finding from a recorded execution.

    Body: {"finding_id": "..."}
    Returns: the new attack_runner result (status + findings + evidence).
    """
    data = request.get_json() or {}
    finding_id = data.get("finding_id")
    if not finding_id:
        return jsonify({"error": "finding_id required"}), 400

    execution = AttackExecution.query.get(execution_id)
    if not execution:
        return jsonify({"error": "execution not found"}), 404
    if not execution.evidence:
        return jsonify({"error": "no evidence on execution"}), 400

    try:
        parsed = json.loads(execution.evidence)
    except Exception:
        return jsonify({"error": "could not parse evidence"}), 400

    finding = _find_in_evidence_blob(parsed, finding_id)
    if not finding:
        return jsonify({"error": "finding not found in execution"}), 404

    attack = Attack.query.get(execution.attack_id)
    if not attack:
        return jsonify({"error": "underlying attack not found"}), 404

    target = Target.query.get(execution.target_id)
    if not target:
        return jsonify({"error": "target not found"}), 404

    # Reconstruct target dict + reuse the original config_used so we hit
    # the same code path with the same params.
    try:
        cfg = json.loads(execution.config_used) if execution.config_used else {}
    except Exception:
        cfg = {}
    # Narrow: replay only this finding's tool/parameter
    replay_params = dict(cfg)
    if finding.get("tool"):
        replay_params["only_tool_names"] = [finding["tool"]]
    if finding.get("parameter"):
        replay_params["only_parameter"] = finding["parameter"]

    target_config = {
        "host": target.host, "port": target.port,
        "protocol": target.protocol, "base_url": target.base_url,
        "target_type": target.target_type, "target_id": target.id,
    }
    if target.auth_config:
        try:
            target_config["auth_config"] = json.loads(target.auth_config)
        except Exception:
            pass
    target_config = attack_runner.prepare_target_dict(target_config,
                                                       target_row=target)

    try:
        attack_tags = json.loads(attack.tags) if attack.tags else []
    except Exception:
        attack_tags = []

    result = attack_runner.run_python_attack(
        attack.script_content,
        target=target_config,
        params=replay_params,
        attack_id=attack.id,
        timeout=attack.timeout or 300,
        execution_id=f"replay-{execution.id[:8]}-{finding_id[:8]}",
        engagement_id=execution.engagement_id,
        attack_tags=attack_tags,
        attack_name=attack.name,
    )

    audit_service.append(
        action="finding_replayed",
        user_id=get_jwt_identity(),
        engagement_id=execution.engagement_id,
        resource_type="finding",
        resource_id=finding_id,
        details={
            "execution_id": execution.id,
            "attack_id": attack.id,
            "target_id": target.id,
            "tool": finding.get("tool"),
            "parameter": finding.get("parameter"),
            "new_findings": len(result.get("findings", [])),
            "status": (result.get("summary") or {}).get("status"),
        },
        ip_address=request.remote_addr,
    )

    return jsonify({
        "execution_id": execution.id,
        "finding_id": finding_id,
        "result": result,
        "reproduced": len(result.get("findings", [])) > 0,
    }), 200
