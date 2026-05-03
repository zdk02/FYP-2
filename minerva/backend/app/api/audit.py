"""
Audit log API.

Read-only browsing of the hash-chained audit log + chain integrity
verification endpoint.
"""

from __future__ import annotations

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from app.api import api_bp
from app.models import AuditLog
from app.services import audit_service


@api_bp.route('/audit', methods=['GET'])
@jwt_required()
def list_audit():
    limit = min(int(request.args.get('limit', 200) or 200), 2000)
    offset = int(request.args.get('offset', 0) or 0)
    action = request.args.get('action')
    engagement_id = request.args.get('engagement_id')
    user_id = request.args.get('user_id')

    q = AuditLog.query
    if action:
        q = q.filter(AuditLog.action == action)
    if engagement_id:
        q = q.filter(AuditLog.engagement_id == engagement_id)
    if user_id:
        q = q.filter(AuditLog.user_id == user_id)

    total = q.count()
    rows = (q.order_by(AuditLog.sequence.desc().nullslast(),
                       AuditLog.created_at.desc())
              .offset(offset).limit(limit).all())
    return jsonify({
        'total': total,
        'limit': limit,
        'offset': offset,
        'entries': [r.to_dict() for r in rows],
    }), 200


@api_bp.route('/audit/verify', methods=['POST'])
@jwt_required()
def verify_audit_chain():
    """Walk the chain and report any break."""
    res = audit_service.verify_chain()
    return jsonify(res), 200
