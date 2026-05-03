"""
Findings triage API — cross-run dedup + FP marking + diff reports.

The runner stamps every finding with a `dedup_key`. This API lets
operators / analysts mark findings as false-positive / accepted /
fixed; that state is remembered across runs of the same engagement.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections import defaultdict

from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from app.api import api_bp
from app.models import (AttackExecution, Engagement, FindingTriage, Target,
                        User)
from app.services import audit_service


VALID_STATUSES = {'open', 'false_positive', 'accepted', 'fixed'}


def _user_role():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    return uid, (u.role if u else None)


@api_bp.route('/findings/triage', methods=['GET'])
@jwt_required()
def list_triage():
    """List triage rows for an engagement."""
    engagement_id = request.args.get('engagement_id')
    status = request.args.get('status')
    q = FindingTriage.query
    if engagement_id:
        q = q.filter(FindingTriage.engagement_id == engagement_id)
    if status:
        q = q.filter(FindingTriage.status == status)
    rows = q.order_by(FindingTriage.last_seen.desc()).limit(2000).all()
    return jsonify([r.to_dict() for r in rows]), 200


@api_bp.route('/findings/triage', methods=['POST'])
@jwt_required()
def upsert_triage():
    """Upsert a triage row for a finding (called automatically by the
    runner via `record_finding`, but exposed for manual sync too)."""
    uid, role = _user_role()
    if role not in ('admin', 'operator', 'manager', 'analyst'):
        return jsonify({'error': 'requires triage role'}), 403
    data = request.get_json() or {}
    if not data.get('dedup_key'):
        return jsonify({'error': 'dedup_key required'}), 400

    row = FindingTriage.query.filter_by(dedup_key=data['dedup_key']).first()
    now = _dt.datetime.utcnow()
    if not row:
        row = FindingTriage(
            dedup_key=data['dedup_key'],
            engagement_id=data.get('engagement_id'),
            target_id=data.get('target_id'),
            attack_id=data.get('attack_id'),
            tool=data.get('tool'),
            parameter=data.get('parameter'),
            payload_class=data.get('payload_class'),
            title=data.get('title'),
            severity=data.get('severity'),
            status=data.get('status') or 'open',
            confidence=data.get('confidence'),
            first_seen=now,
        )
        db.session.add(row)
    else:
        for f in ('engagement_id', 'target_id', 'attack_id', 'tool',
                  'parameter', 'payload_class', 'title', 'severity',
                  'confidence'):
            if data.get(f):
                setattr(row, f, data[f])
    row.last_seen = now
    if data.get('last_run_id'):
        row.last_run_id = data['last_run_id']
    db.session.commit()
    return jsonify(row.to_dict()), 200


@api_bp.route('/findings/triage/<triage_id>/status', methods=['POST'])
@jwt_required()
def set_triage_status(triage_id):
    uid, role = _user_role()
    if role not in ('admin', 'operator', 'manager', 'analyst'):
        return jsonify({'error': 'requires triage role'}), 403
    row = FindingTriage.query.get(triage_id)
    if not row:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json() or {}
    status = (data.get('status') or '').strip()
    if status not in VALID_STATUSES:
        return jsonify({'error': f'status must be one of {sorted(VALID_STATUSES)}'}), 400

    prev = row.status
    row.status = status
    row.triaged_by = uid
    row.triage_note = data.get('note')
    if status == 'false_positive':
        row.fp_history = (row.fp_history or 0) + 1
    elif status in ('open', 'accepted', 'fixed') and prev == 'false_positive':
        # no-op for tp_history; tp is incremented by the runner
        pass
    db.session.commit()

    audit_service.append(
        action='finding_triaged',
        user_id=uid,
        engagement_id=row.engagement_id,
        resource_type='finding_triage',
        resource_id=row.id,
        details={'dedup_key': row.dedup_key, 'status': status,
                 'prev': prev, 'note': data.get('note')},
        ip_address=request.remote_addr,
    )
    return jsonify(row.to_dict()), 200


# ---------------------------------------------------------------------------
# Diff between two runs in the same engagement
# ---------------------------------------------------------------------------

def _findings_from_execution(execution: AttackExecution) -> list[dict]:
    if not execution or not execution.evidence:
        return []
    try:
        data = json.loads(execution.evidence)
    except Exception:
        return []
    if isinstance(data, list):
        # legacy: was an evidence array — try to read 'findings' key on
        # the parent shape instead
        return []
    if isinstance(data, dict):
        return list(data.get('findings') or [])
    return []


@api_bp.route('/findings/diff', methods=['POST'])
@jwt_required()
def diff_runs():
    """Diff two campaign runs (or any two AttackExecution runs).

    Body: {"run_a_id": "...", "run_b_id": "..."}
    Returns: {new, fixed, regressed, unchanged}
    """
    data = request.get_json() or {}
    a_id = data.get('run_a_id')
    b_id = data.get('run_b_id')
    if not a_id or not b_id:
        return jsonify({'error': 'run_a_id and run_b_id required'}), 400

    a = AttackExecution.query.get(a_id)
    b = AttackExecution.query.get(b_id)
    if not a or not b:
        return jsonify({'error': 'one or both runs not found'}), 404

    a_findings = _findings_from_execution(a)
    b_findings = _findings_from_execution(b)
    a_keys = {f.get('dedup_key'): f for f in a_findings if f.get('dedup_key')}
    b_keys = {f.get('dedup_key'): f for f in b_findings if f.get('dedup_key')}

    new = [b_keys[k] for k in b_keys if k not in a_keys]
    fixed = [a_keys[k] for k in a_keys if k not in b_keys]
    unchanged = [b_keys[k] for k in b_keys if k in a_keys
                 and a_keys[k].get('severity') == b_keys[k].get('severity')]
    regressed = [b_keys[k] for k in b_keys if k in a_keys
                 and a_keys[k].get('severity') != b_keys[k].get('severity')]

    return jsonify({
        'run_a': {'id': a.id, 'started_at': a.started_at.isoformat() if a.started_at else None,
                  'count': len(a_findings)},
        'run_b': {'id': b.id, 'started_at': b.started_at.isoformat() if b.started_at else None,
                  'count': len(b_findings)},
        'new_count': len(new),
        'fixed_count': len(fixed),
        'unchanged_count': len(unchanged),
        'regressed_count': len(regressed),
        'new': new[:200],
        'fixed': fixed[:200],
        'regressed': regressed[:200],
    }), 200
