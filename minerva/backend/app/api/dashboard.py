"""
Dashboard API — aggregate counters and activity feed for the home page.

These endpoints intentionally avoid heavy joins so the dashboard stays
responsive even when there are tens of thousands of executions.
"""

from flask import jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import func

from app.api import api_bp
from app import db
from app.models.models import (
    Attack, Target, Campaign, Report, AttackExecution, AuditLog, ScanJob,
)
from datetime import datetime, timedelta


def _humanize(delta: timedelta) -> str:
    s = int(delta.total_seconds())
    if s < 60:
        return f'{s}s ago'
    if s < 3600:
        return f'{s // 60}m ago'
    if s < 86400:
        return f'{s // 3600}h ago'
    return f'{s // 86400}d ago'


@api_bp.route('/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    """Top-line counters and severity breakdown for the dashboard."""
    total_attacks = db.session.query(func.count(Attack.id)).scalar() or 0
    active_targets = db.session.query(func.count(Target.id)).filter(
        Target.is_active.is_(True)
    ).scalar() or 0
    running_campaigns = db.session.query(func.count(Campaign.id)).filter(
        Campaign.status.in_(['active', 'running'])
    ).scalar() or 0
    reports_generated = db.session.query(func.count(Report.id)).scalar() or 0

    severity_rows = db.session.query(
        AttackExecution.severity_found, func.count(AttackExecution.id)
    ).filter(
        AttackExecution.result == 'vulnerable'
    ).group_by(AttackExecution.severity_found).all()

    severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for sev, count in severity_rows:
        key = (sev or 'info').lower()
        if key in severity:
            severity[key] = count

    total_executions = db.session.query(func.count(AttackExecution.id)).scalar() or 0
    vulnerable_executions = db.session.query(func.count(AttackExecution.id)).filter(
        AttackExecution.result == 'vulnerable'
    ).scalar() or 0
    failed_executions = db.session.query(func.count(AttackExecution.id)).filter(
        AttackExecution.status.in_(['failed', 'error'])
    ).scalar() or 0
    completed_scans = db.session.query(func.count(ScanJob.id)).filter(
        ScanJob.status == 'completed'
    ).scalar() or 0

    return jsonify({
        'total_attacks': total_attacks,
        'active_targets': active_targets,
        'running_campaigns': running_campaigns,
        'reports_generated': reports_generated,
        'total_executions': total_executions,
        'vulnerable_executions': vulnerable_executions,
        'failed_executions': failed_executions,
        'completed_scans': completed_scans,
        'severity_breakdown': severity,
    })


@api_bp.route('/dashboard/activity', methods=['GET'])
@jwt_required()
def dashboard_activity():
    """Most-recent platform activity, fused from campaigns, executions,
    scans, and reports — newest first."""
    now = datetime.utcnow()
    items = []

    recent_campaigns = Campaign.query.order_by(Campaign.updated_at.desc()).limit(8).all()
    for c in recent_campaigns:
        ts = getattr(c, 'updated_at', None) or c.created_at
        if not ts:
            continue
        if c.status == 'completed':
            action = f'Campaign "{c.name}" completed'
            status = 'success'
        elif c.status in ('active', 'running'):
            action = f'Campaign "{c.name}" running'
            status = 'pending'
        elif c.status == 'paused':
            action = f'Campaign "{c.name}" paused'
            status = 'warning'
        else:
            action = f'Campaign "{c.name}" {c.status}'
            status = 'pending'
        items.append({
            'kind': 'campaign',
            'action': action,
            'target': '',
            'status': status,
            'time': _humanize(now - ts),
            'created_at': ts.isoformat(),
            'id': c.id,
        })

    recent_findings = AttackExecution.query.filter(
        AttackExecution.result == 'vulnerable'
    ).order_by(AttackExecution.created_at.desc()).limit(8).all()
    for e in recent_findings:
        ts = e.completed_at or e.created_at
        if not ts:
            continue
        attack = Attack.query.get(e.attack_id) if e.attack_id else None
        target = Target.query.get(e.target_id) if e.target_id else None
        sev = (e.severity_found or '').lower()
        status = 'error' if sev == 'critical' else ('warning' if sev in ('high', 'medium') else 'success')
        items.append({
            'kind': 'finding',
            'action': f'{(sev or "Finding").title()} severity finding'
                      f'{f" — {attack.name}" if attack else ""}',
            'target': (target.name if target else '') or '',
            'status': status,
            'time': _humanize(now - ts),
            'created_at': ts.isoformat(),
            'id': e.id,
        })

    recent_scans = ScanJob.query.order_by(ScanJob.created_at.desc()).limit(6).all()
    for s in recent_scans:
        ts = s.completed_at or s.started_at or s.created_at
        if not ts:
            continue
        if s.status == 'completed':
            status = 'success'
        elif s.status in ('failed', 'error'):
            status = 'error'
        elif s.status == 'running':
            status = 'pending'
        else:
            status = 'pending'
        items.append({
            'kind': 'scan',
            'action': f'Scan "{s.name}" {s.status}',
            'target': s.target_range or '',
            'status': status,
            'time': _humanize(now - ts),
            'created_at': ts.isoformat(),
            'id': s.id,
        })

    items.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({'activity': items[:15]})


@api_bp.route('/dashboard/audit-summary', methods=['GET'])
@jwt_required()
def dashboard_audit_summary():
    """Recent admin actions — useful for ops awareness on a shared instance."""
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    return jsonify({
        'logs': [{
            'id': log.id,
            'action': log.action,
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'created_at': log.created_at.isoformat() if log.created_at else None,
        } for log in logs]
    })
