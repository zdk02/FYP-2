"""
Engagement API — legal-scope authorization layer.

Every attack run is bound to an engagement; this is where engagements
are created, updated, scoped, signed off, killed, and reset.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import secrets

from flask import jsonify, request, send_from_directory
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

from app import db
from app.api import api_bp
from app.api.users import admin_required
from app.models import Engagement, User
from app.services import audit_service, engagement_service


def _current_user():
    uid = get_jwt_identity()
    return User.query.get(uid) if uid else None


def _require_role(*roles):
    """Inline RBAC check. Returns (None, None) if allowed; (response, code)
    if not. The decorators in users.py only cover admin/manager — we
    need finer-grained control for operator vs analyst vs viewer."""
    u = _current_user()
    if not u:
        return jsonify({'error': 'Authentication required'}), 401
    if u.role not in roles:
        return jsonify({'error': f'Requires one of: {", ".join(roles)}'}), 403
    return None


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@api_bp.route('/engagements', methods=['GET'])
@jwt_required()
def list_engagements():
    items = Engagement.query.order_by(
        Engagement.is_active_default.desc(),
        Engagement.created_at.desc(),
    ).all()
    return jsonify([e.to_dict() for e in items]), 200


@api_bp.route('/engagements/active', methods=['GET'])
@jwt_required()
def get_active_engagement():
    eng = engagement_service.get_active_engagement()
    if not eng:
        return jsonify({'engagement': None}), 200
    return jsonify({'engagement': eng.to_dict()}), 200


@api_bp.route('/engagements/<eng_id>', methods=['GET'])
@jwt_required()
def get_engagement(eng_id):
    eng = Engagement.query.get(eng_id)
    if not eng:
        return jsonify({'error': 'Engagement not found'}), 404
    return jsonify(eng.to_dict()), 200


@api_bp.route('/engagements', methods=['POST'])
@jwt_required()
def create_engagement():
    err = _require_role('admin', 'operator', 'manager')
    if err:
        return err
    data = request.get_json() or {}
    if not data.get('name'):
        return jsonify({'error': 'name required'}), 400
    if not data.get('authorized_targets'):
        return jsonify({'error': 'authorized_targets required (at least one)'}), 400

    eng = Engagement(
        name=data['name'],
        client_name=data.get('client_name'),
        description=data.get('description'),
        signed_off_by=data.get('signed_off_by'),
        rules_of_engagement=data.get('rules_of_engagement'),
        authorized_targets=json.dumps(data.get('authorized_targets') or []),
        max_requests=int(data.get('max_requests') or 100000),
        max_wall_seconds=int(data.get('max_wall_seconds') or 14400),
        max_concurrent=int(data.get('max_concurrent') or 4),
        safe_mode=bool(data.get('safe_mode')),
        dry_run_default=bool(data.get('dry_run_default')),
        webhook_url=data.get('webhook_url'),
        webhook_secret=data.get('webhook_secret') or secrets.token_hex(16),
        slack_url=data.get('slack_url'),
        teams_url=data.get('teams_url'),
        notify_min_severity=data.get('notify_min_severity') or 'high',
        status=data.get('status') or 'active',
        is_active_default=bool(data.get('is_active_default')),
        health_threshold_x=float(data.get('health_threshold_x') or 3.0),
        created_by=get_jwt_identity(),
    )
    if data.get('time_window_start'):
        eng.time_window_start = _dt.datetime.fromisoformat(
            data['time_window_start'].replace('Z', '+00:00'))
    if data.get('time_window_end'):
        eng.time_window_end = _dt.datetime.fromisoformat(
            data['time_window_end'].replace('Z', '+00:00'))

    if eng.is_active_default:
        # Demote any other active default
        Engagement.query.filter(
            Engagement.id != eng.id,
            Engagement.is_active_default == True  # noqa: E712
        ).update({'is_active_default': False})

    db.session.add(eng)
    db.session.commit()

    audit_service.append(
        action='engagement_created',
        user_id=get_jwt_identity(),
        engagement_id=eng.id,
        resource_type='engagement',
        resource_id=eng.id,
        details={'name': eng.name, 'allowlist': data.get('authorized_targets')},
        ip_address=request.remote_addr,
    )
    return jsonify(eng.to_dict()), 201


@api_bp.route('/engagements/<eng_id>', methods=['PUT'])
@jwt_required()
def update_engagement(eng_id):
    err = _require_role('admin', 'operator', 'manager')
    if err:
        return err
    eng = Engagement.query.get(eng_id)
    if not eng:
        return jsonify({'error': 'Engagement not found'}), 404
    data = request.get_json() or {}

    simple = ['name', 'client_name', 'description', 'signed_off_by',
              'rules_of_engagement', 'webhook_url', 'webhook_secret',
              'slack_url', 'teams_url', 'notify_min_severity', 'status']
    for f in simple:
        if f in data:
            setattr(eng, f, data[f])
    if 'authorized_targets' in data:
        eng.authorized_targets = json.dumps(data['authorized_targets'] or [])
    for f in ['max_requests', 'max_wall_seconds', 'max_concurrent']:
        if f in data and data[f] is not None:
            setattr(eng, f, int(data[f]))
    for f in ['safe_mode', 'dry_run_default']:
        if f in data:
            setattr(eng, f, bool(data[f]))
    if 'health_threshold_x' in data:
        eng.health_threshold_x = float(data['health_threshold_x'] or 3.0)
    if 'time_window_start' in data:
        eng.time_window_start = (
            _dt.datetime.fromisoformat(data['time_window_start'].replace('Z', '+00:00'))
            if data['time_window_start'] else None)
    if 'time_window_end' in data:
        eng.time_window_end = (
            _dt.datetime.fromisoformat(data['time_window_end'].replace('Z', '+00:00'))
            if data['time_window_end'] else None)
    if 'is_active_default' in data and data['is_active_default']:
        Engagement.query.filter(
            Engagement.id != eng.id,
            Engagement.is_active_default == True  # noqa: E712
        ).update({'is_active_default': False})
        eng.is_active_default = True
    elif 'is_active_default' in data:
        eng.is_active_default = False

    db.session.commit()
    audit_service.append(
        action='engagement_updated',
        user_id=get_jwt_identity(),
        engagement_id=eng.id,
        resource_type='engagement',
        resource_id=eng.id,
        details={k: data.get(k) for k in data if k != 'webhook_secret'},
        ip_address=request.remote_addr,
    )
    return jsonify(eng.to_dict()), 200


@api_bp.route('/engagements/<eng_id>', methods=['DELETE'])
@admin_required
def delete_engagement(eng_id):
    eng = Engagement.query.get(eng_id)
    if not eng:
        return jsonify({'error': 'Engagement not found'}), 404
    audit_service.append(
        action='engagement_deleted',
        user_id=get_jwt_identity(),
        engagement_id=eng.id,
        resource_type='engagement',
        resource_id=eng.id,
        details={'name': eng.name},
        ip_address=request.remote_addr,
    )
    db.session.delete(eng)
    db.session.commit()
    return jsonify({'message': 'Engagement deleted'}), 200


# ---------------------------------------------------------------------------
# Activation / kill switch / quota reset
# ---------------------------------------------------------------------------

@api_bp.route('/engagements/<eng_id>/activate', methods=['POST'])
@jwt_required()
def activate_engagement(eng_id):
    err = _require_role('admin', 'operator', 'manager')
    if err:
        return err
    eng = Engagement.query.get(eng_id)
    if not eng:
        return jsonify({'error': 'Engagement not found'}), 404
    Engagement.query.filter(
        Engagement.id != eng.id,
        Engagement.is_active_default == True  # noqa: E712
    ).update({'is_active_default': False})
    eng.is_active_default = True
    eng.status = 'active'
    db.session.commit()
    audit_service.append(
        action='engagement_activated',
        user_id=get_jwt_identity(),
        engagement_id=eng.id,
        resource_type='engagement',
        resource_id=eng.id,
        ip_address=request.remote_addr,
    )
    return jsonify(eng.to_dict()), 200


@api_bp.route('/engagements/<eng_id>/kill', methods=['POST'])
@jwt_required()
def kill_engagement(eng_id):
    err = _require_role('admin', 'operator', 'manager')
    if err:
        return err
    if not engagement_service.kill(eng_id):
        return jsonify({'error': 'Engagement not found'}), 404
    audit_service.append(
        action='engagement_killed',
        user_id=get_jwt_identity(),
        engagement_id=eng_id,
        resource_type='engagement',
        resource_id=eng_id,
        ip_address=request.remote_addr,
    )
    return jsonify({'message': 'Kill switch engaged'}), 200


@api_bp.route('/engagements/<eng_id>/revive', methods=['POST'])
@jwt_required()
def revive_engagement(eng_id):
    err = _require_role('admin', 'operator', 'manager')
    if err:
        return err
    if not engagement_service.revive(eng_id):
        return jsonify({'error': 'Engagement not found'}), 404
    audit_service.append(
        action='engagement_revived',
        user_id=get_jwt_identity(),
        engagement_id=eng_id,
        resource_type='engagement',
        resource_id=eng_id,
        ip_address=request.remote_addr,
    )
    return jsonify({'message': 'Engagement revived'}), 200


@api_bp.route('/engagements/<eng_id>/reset_quota', methods=['POST'])
@jwt_required()
def reset_engagement_quota(eng_id):
    err = _require_role('admin', 'operator', 'manager')
    if err:
        return err
    if not engagement_service.reset_quota(eng_id):
        return jsonify({'error': 'Engagement not found'}), 404
    audit_service.append(
        action='engagement_quota_reset',
        user_id=get_jwt_identity(),
        engagement_id=eng_id,
        resource_type='engagement',
        resource_id=eng_id,
        ip_address=request.remote_addr,
    )
    return jsonify({'message': 'Quota reset to 0'}), 200


# ---------------------------------------------------------------------------
# SOW upload
# ---------------------------------------------------------------------------

@api_bp.route('/engagements/<eng_id>/sow', methods=['POST'])
@jwt_required()
def upload_sow(eng_id):
    err = _require_role('admin', 'operator', 'manager')
    if err:
        return err
    eng = Engagement.query.get(eng_id)
    if not eng:
        return jsonify({'error': 'Engagement not found'}), 404
    if 'file' not in request.files:
        return jsonify({'error': 'file required'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'empty filename'}), 400
    fname = secure_filename(f.filename)
    sow_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), 'instance', 'sows')
    os.makedirs(sow_dir, exist_ok=True)
    path = os.path.join(sow_dir, f"{eng.id}_{fname}")
    f.save(path)
    eng.sow_filename = fname
    eng.sow_path = path
    db.session.commit()
    audit_service.append(
        action='sow_uploaded',
        user_id=get_jwt_identity(),
        engagement_id=eng.id,
        resource_type='engagement',
        resource_id=eng.id,
        details={'filename': fname},
        ip_address=request.remote_addr,
    )
    return jsonify(eng.to_dict()), 200


@api_bp.route('/engagements/<eng_id>/sow', methods=['GET'])
@jwt_required()
def download_sow(eng_id):
    eng = Engagement.query.get(eng_id)
    if not eng or not eng.sow_path or not os.path.exists(eng.sow_path):
        return jsonify({'error': 'SOW not found'}), 404
    return send_from_directory(
        os.path.dirname(eng.sow_path),
        os.path.basename(eng.sow_path),
        as_attachment=True,
        download_name=eng.sow_filename or os.path.basename(eng.sow_path),
    )


# ---------------------------------------------------------------------------
# Scope check (used by UI to show banner)
# ---------------------------------------------------------------------------

@api_bp.route('/engagements/<eng_id>/check_scope', methods=['POST'])
@jwt_required()
def check_scope(eng_id):
    eng = Engagement.query.get(eng_id)
    if not eng:
        return jsonify({'error': 'Engagement not found'}), 404
    data = request.get_json() or {}
    host = (data.get('host') or '').strip()
    if not host:
        return jsonify({'error': 'host required'}), 400
    return jsonify({
        'engagement_id': eng.id,
        'host': host,
        'in_scope': engagement_service.is_target_authorized(eng, host),
    }), 200
