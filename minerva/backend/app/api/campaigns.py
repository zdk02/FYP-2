"""
Campaign Management API Routes
Handles penetration testing campaigns, execution, and monitoring
"""

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app import db
from app.models.models import (
    Campaign, Target, Attack, AttackExecution, User, AuditLog
)
from datetime import datetime
import json



def require_role(*roles):
    """Decorator to check user role"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user or user.role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def log_action(user_id, action, entity_type, entity_id=None, details=None):
    """Create an audit log entry"""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=entity_type,
        resource_id=entity_id,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:500]
    )
    db.session.add(log)


def _serialize_campaign(c, *, with_relations=False, stats=None):
    targets = list(c.targets) if with_relations else []
    attacks = list(c.attacks) if with_relations else []
    return {
        'id': c.id,
        'name': c.name,
        'description': c.description,
        'status': c.status,
        'campaign_type': c.campaign_type,
        'mode': c.mode,
        'scenario': c.scenario,
        'progress': c.progress,
        'scope_definition': json.loads(c.scope_definition) if c.scope_definition else {},
        'scope': json.loads(c.scope_definition) if c.scope_definition else {},
        'rules_of_engagement': c.rules_of_engagement,
        'target_ids': [t.id for t in targets] if with_relations else None,
        'attack_ids': [a.id for a in attacks] if with_relations else None,
        'targets': [{'id': t.id, 'name': t.name, 'host': t.host} for t in targets] if with_relations else None,
        'attacks': [{'id': a.id, 'name': a.name, 'severity': a.severity} for a in attacks] if with_relations else None,
        'target_count': len(c.targets),
        'attack_count': len(c.attacks),
        'owner_id': c.owner_id,
        'created_by': c.owner_id,
        'start_date': c.start_date.isoformat() if c.start_date else None,
        'end_date': c.end_date.isoformat() if c.end_date else None,
        'started_at': c.start_date.isoformat() if c.start_date else None,
        'completed_at': c.end_date.isoformat() if c.end_date else None,
        'created_at': c.created_at.isoformat() if c.created_at else None,
        'updated_at': c.updated_at.isoformat() if c.updated_at else None,
        'statistics': stats,
    }


@api_bp.route('/campaigns', methods=['GET'])
@jwt_required()
def get_campaigns():
    """Get all campaigns with optional filtering"""
    status = request.args.get('status')
    campaign_type = request.args.get('type')
    mode = request.args.get('mode')
    search = request.args.get('search')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    query = Campaign.query

    if status:
        query = query.filter(Campaign.status == status)
    if campaign_type:
        query = query.filter(Campaign.campaign_type == campaign_type)
    if mode:
        query = query.filter(Campaign.mode == mode)
    if search:
        query = query.filter(
            db.or_(
                Campaign.name.ilike(f'%{search}%'),
                Campaign.description.ilike(f'%{search}%')
            )
        )

    pagination = query.order_by(Campaign.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    campaigns = []
    for c in pagination.items:
        exec_count = AttackExecution.query.filter_by(campaign_id=c.id).count()
        success_count = AttackExecution.query.filter_by(
            campaign_id=c.id, result='vulnerable'
        ).count()
        findings_count = success_count
        completed = AttackExecution.query.filter(
            AttackExecution.campaign_id == c.id,
            AttackExecution.status.in_(
                ('completed', 'success', 'failed', 'error', 'cancelled')
            ),
        ).count()

        campaigns.append({
            **_serialize_campaign(c),
            'execution_count': exec_count,
            'success_count': success_count,
            'findings_count': findings_count,
            'completed_attacks': completed,
            'total_attacks': exec_count,
        })

    return jsonify({
        'campaigns': campaigns,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@api_bp.route('/campaigns/<campaign_id>', methods=['GET'])
@jwt_required()
def get_campaign(campaign_id):
    """Get detailed campaign information"""
    campaign = Campaign.query.get_or_404(campaign_id)

    executions = AttackExecution.query.filter_by(campaign_id=campaign_id).all()
    stats = {
        'total': len(executions),
        'vulnerable': sum(1 for e in executions if e.result == 'vulnerable'),
        'not_vulnerable': sum(1 for e in executions if e.result == 'not_vulnerable'),
        'error': sum(1 for e in executions if e.result == 'error'),
        'pending': sum(1 for e in executions if e.status == 'pending'),
        'running': sum(1 for e in executions if e.status == 'running'),
        'completed': sum(1 for e in executions
                         if e.status in ('completed', 'success', 'failed', 'error', 'cancelled')),
    }

    payload = _serialize_campaign(campaign, with_relations=True, stats=stats)
    payload['findings_count'] = stats['vulnerable']
    payload['completed_attacks'] = stats['completed']
    payload['total_attacks'] = stats['total']
    return jsonify(payload)


@api_bp.route('/campaigns', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def create_campaign():
    """Create a new penetration testing campaign"""
    user_id = get_jwt_identity()
    data = request.get_json() or {}

    if not data.get('name'):
        return jsonify({'error': 'Campaign name is required'}), 400

    scope = data.get('scope') or data.get('scope_definition') or {}
    roe = data.get('rules_of_engagement')
    if isinstance(roe, (dict, list)):
        roe = json.dumps(roe)

    campaign = Campaign(
        name=data['name'],
        description=data.get('description'),
        campaign_type=data.get('campaign_type', 'external'),
        mode=data.get('mode', 'manual'),
        scenario=data.get('scenario', 'direct'),
        scope_definition=json.dumps(scope) if scope else None,
        rules_of_engagement=roe,
        status=data.get('status', 'draft'),
        owner_id=user_id,
    )

    db.session.add(campaign)
    target_ids = data.get('target_ids') or []
    attack_ids = data.get('attack_ids') or []
    if target_ids:
        campaign.targets = Target.query.filter(Target.id.in_(target_ids)).all()
    if attack_ids:
        campaign.attacks = Attack.query.filter(Attack.id.in_(attack_ids)).all()

    log_action(user_id, 'create', 'campaign', details=f'Created campaign: {campaign.name}')
    db.session.commit()

    return jsonify({
        'message': 'Campaign created successfully',
        'campaign': {
            'id': campaign.id,
            'name': campaign.name,
            'status': campaign.status
        }
    }), 201


@api_bp.route('/campaigns/<campaign_id>', methods=['PUT'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def update_campaign(campaign_id):
    """Update campaign details"""
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)
    data = request.get_json() or {}

    if campaign.status in ('running', 'active'):
        return jsonify({'error': 'Cannot update a running campaign'}), 400

    if 'name' in data:
        campaign.name = data['name']
    if 'description' in data:
        campaign.description = data['description']
    if 'campaign_type' in data:
        campaign.campaign_type = data['campaign_type']
    if 'mode' in data:
        campaign.mode = data['mode']
    if 'scenario' in data:
        campaign.scenario = data['scenario']
    if 'scope' in data or 'scope_definition' in data:
        scope = data.get('scope') or data.get('scope_definition') or {}
        campaign.scope_definition = json.dumps(scope) if scope else None
    if 'rules_of_engagement' in data:
        roe = data['rules_of_engagement']
        campaign.rules_of_engagement = json.dumps(roe) if isinstance(roe, (dict, list)) else roe
    if 'target_ids' in data:
        ids = data.get('target_ids') or []
        campaign.targets = Target.query.filter(Target.id.in_(ids)).all() if ids else []
    if 'attack_ids' in data:
        ids = data.get('attack_ids') or []
        campaign.attacks = Attack.query.filter(Attack.id.in_(ids)).all() if ids else []

    log_action(user_id, 'update', 'campaign', campaign_id, f'Updated campaign: {campaign.name}')
    db.session.commit()

    return jsonify({'message': 'Campaign updated successfully'})


@api_bp.route('/campaigns/<campaign_id>', methods=['DELETE'])
@jwt_required()
@require_role('admin', 'manager')
def delete_campaign(campaign_id):
    """Delete a campaign"""
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)

    if campaign.status in ('running', 'active'):
        return jsonify({'error': 'Cannot delete a running campaign'}), 400

    campaign_name = campaign.name
    db.session.delete(campaign)
    log_action(user_id, 'delete', 'campaign', campaign_id, f'Deleted campaign: {campaign_name}')
    db.session.commit()

    return jsonify({'message': 'Campaign deleted successfully'})


def _running_states():
    return ('running', 'active')


_CWE_TO_ATTACK_TAG = {
    'CWE-78':  'command_injection',
    'CWE-89':  'sql_injection',
    'CWE-94':  'rce',
    'CWE-22':  'path_traversal',
    'CWE-918': 'ssrf',
    'CWE-77':  'prompt_injection',
    'CWE-502': 'deserialization',
    'CWE-287': 'auth_bypass',
    'CWE-306': 'auth_bypass',
    'CWE-200': 'info_disclosure',
    'CWE-532': 'info_disclosure',
    'CWE-319': 'mitm',
    'CWE-326': 'mitm',
    'CWE-770': 'dos',
    'CWE-674': 'dos',
}


def _maybe_add_attacks(campaign_id, existing_attack_ids, scan_findings):
    """After a background scan completes, add active attacks whose tags
    overlap with the scanner's CWE / category hits. Idempotent — won't
    add duplicates."""
    wanted = set()
    for f in scan_findings:
        cwe = (f.get('cwe') or '').upper()
        cat = (f.get('category') or '').lower()
        if cwe in _CWE_TO_ATTACK_TAG:
            wanted.add(_CWE_TO_ATTACK_TAG[cwe])
        if cat:
            wanted.add(cat)
    if not wanted:
        return
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return
    current_ids = {a.id for a in campaign.attacks} | set(existing_attack_ids or [])
    pool = Attack.query.filter(Attack.is_active == True).all()  # noqa: E712
    for atk in pool:
        if atk.id in current_ids:
            continue
        tag_blob = ''
        raw = getattr(atk, 'tags', None)
        if isinstance(raw, str):
            tag_blob = raw.lower()
        elif isinstance(raw, (list, tuple)):
            tag_blob = ' '.join(str(t).lower() for t in raw)
        if any(t in tag_blob for t in wanted):
            campaign.attacks.append(atk)
            current_ids.add(atk.id)
    db.session.commit()


@api_bp.route('/campaigns/<campaign_id>/start', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def start_campaign(campaign_id):
    """Start campaign execution.

    If the campaign's `scope_definition` includes `phases: ["scan", "exploit"]`
    (or `phases: ["scan"]`), Minerva runs the configured scanner plugins
    against every target FIRST, persists the scan findings, and (optionally)
    uses the scan results to scope or expand the attack set before queuing
    AttackExecutions. See campaigns/scan_first.md.
    """
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)

    if campaign.status in _running_states():
        return jsonify({'error': 'Campaign is already running'}), 400
    if campaign.status == 'completed':
        return jsonify({'error': 'Campaign is already completed. Clone it to run again.'}), 400

    # Pull phase config out of scope_definition
    scope_cfg = {}
    if campaign.scope_definition:
        try:
            scope_cfg = json.loads(campaign.scope_definition) or {}
        except Exception:
            scope_cfg = {}
    phases = scope_cfg.get('phases') or ['exploit']
    scan_plugin_ids = scope_cfg.get('scan_plugins') or [
        'client_vuln_scanner', 'server_vuln_scanner',
    ]
    auto_select_from_scan = bool(scope_cfg.get('auto_select_attacks_from_scan', False))
    scan_params = scope_cfg.get('scan_params') or {}

    targets = list(campaign.targets)
    attacks = list(campaign.attacks)

    if not targets:
        return jsonify({'error': 'No targets configured for this campaign'}), 400
    if not attacks and 'scan' not in phases:
        return jsonify({'error': 'No attacks configured for this campaign'}), 400

    campaign.status = 'active'
    campaign.start_date = datetime.utcnow()
    campaign.progress = 0

    # ── Phase 1: queue exploit executions FIRST (so the UI shows the plan)─
    # In manual mode, executions sit in 'pending' until the user runs them
    # (per-execution Run button, batch-run, or by switching to automated).
    if 'exploit' in phases and campaign.mode != 'automated':
        for target in targets:
            for attack in attacks:
                execution = AttackExecution(
                    campaign_id=campaign.id,
                    attack_id=attack.id,
                    target_id=target.id,
                    status='pending',
                    config_used=json.dumps({
                        'scenario': campaign.scenario,
                        'mode': campaign.mode,
                        'phase': 'exploit',
                    }),
                    executed_by=user_id,
                )
                db.session.add(execution)

    log_action(user_id, 'start', 'campaign', campaign_id,
               f'Started campaign: {campaign.name} (phases={phases})')
    db.session.commit()

    # ── Phase 2: scan, runs in a BACKGROUND THREAD so we don't block ─────
    # The thread updates the DB asynchronously; the UI sees scan findings
    # appear over the next ~30-60s. start_campaign returns immediately.
    if 'scan' in phases:
        from flask import current_app as _ca
        _app = _ca._get_current_object()
        target_dicts = [{
            'id': t.id, 'name': t.name,
            'host': t.host, 'port': t.port, 'protocol': t.protocol,
            'base_url': getattr(t, 'base_url', None) or
                        f"{t.protocol}://{t.host}:{t.port}",
            'auth_config': getattr(t, 'auth_config', None) or {},
        } for t in targets]
        attack_ids = [a.id for a in attacks]

        def _bg_scan():
            try:
                from app.services import scanner_runner, scanner_registry
            except Exception as e:
                with _app.app_context():
                    log_action(user_id, 'scan_error', 'campaign', campaign_id,
                               f'scan import error: {e!s:.200}')
                    db.session.commit()
                return
            for tdict in target_dicts:
                for plugin_id in scan_plugin_ids:
                    try:
                        with _app.app_context():
                            scanner_registry.plugin_dir(plugin_id)
                    except Exception:
                        continue
                    try:
                        with _app.app_context():
                            res = scanner_runner.run_scanner(
                                plugin_id, tdict, scan_params,
                            )
                            findings_count = len(res.get('findings') or [])
                            log_action(
                                user_id, 'scan_complete', 'campaign',
                                campaign_id,
                                f'{plugin_id} on {tdict["name"]}: '
                                f'{findings_count} findings'
                            )
                            db.session.commit()
                            # Auto-select attacks
                            if auto_select_from_scan and (res.get('findings') or []):
                                _maybe_add_attacks(
                                    campaign_id, attack_ids,
                                    res.get('findings') or [],
                                )
                    except Exception as e:
                        with _app.app_context():
                            log_action(user_id, 'scan_error', 'campaign',
                                       campaign_id,
                                       f'{plugin_id} on {tdict["name"]}: '
                                       f'{e!s:.300}')
                            db.session.commit()

        import threading as _threading
        _threading.Thread(target=_bg_scan, daemon=True).start()
        scan_summary = [{'queued': len(target_dicts) * len(scan_plugin_ids)}]
    else:
        scan_summary = []
    auto_added = []
    scan_findings = []

    if campaign.mode == 'automated':
        try:
            from app.services.attack_service import AttackExecutor
            from app.api.executions import update_campaign_progress
            executor = AttackExecutor()
            executor.execute_campaign(campaign_id, user_id, 'sequential')
            update_campaign_progress(campaign_id)
        except Exception as e:
            return jsonify({
                'message': 'Campaign started but background execution failed to launch',
                'status': campaign.status,
                'error': str(e)[:300],
            }), 200

    return jsonify({
        'message': 'Campaign started successfully',
        'status': campaign.status,
        'phases': phases,
        'scan_phase': {
            'plugins': scan_plugin_ids if 'scan' in phases else [],
            'summary': scan_summary,
            'findings_count': len(scan_findings),
        },
        'auto_added_attacks': auto_added,
        'total_executions': len(targets) * len(attacks) if 'exploit' in phases else 0,
    })


@api_bp.route('/campaigns/<campaign_id>/pause', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def pause_campaign(campaign_id):
    """Pause a running campaign without cancelling pending executions."""
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)

    if campaign.status not in _running_states():
        return jsonify({'error': 'Campaign is not running'}), 400

    campaign.status = 'paused'
    log_action(user_id, 'pause', 'campaign', campaign_id, f'Paused campaign: {campaign.name}')
    db.session.commit()
    return jsonify({'message': 'Campaign paused successfully'})


@api_bp.route('/campaigns/<campaign_id>/stop', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def stop_campaign(campaign_id):
    """Stop a running or paused campaign and cancel pending executions."""
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)

    if campaign.status not in (*_running_states(), 'paused'):
        return jsonify({'error': 'Campaign is not running'}), 400

    campaign.status = 'stopped'

    AttackExecution.query.filter_by(
        campaign_id=campaign_id, status='pending'
    ).update({'status': 'cancelled'})

    log_action(user_id, 'stop', 'campaign', campaign_id, f'Stopped campaign: {campaign.name}')
    db.session.commit()

    return jsonify({'message': 'Campaign stopped successfully'})


@api_bp.route('/campaigns/<campaign_id>/resume', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def resume_campaign(campaign_id):
    """Resume a paused or stopped campaign"""
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)

    if campaign.status not in ('stopped', 'paused'):
        return jsonify({'error': 'Campaign cannot be resumed'}), 400

    campaign.status = 'active'

    AttackExecution.query.filter_by(
        campaign_id=campaign_id, status='cancelled'
    ).update({'status': 'pending'})

    log_action(user_id, 'resume', 'campaign', campaign_id, f'Resumed campaign: {campaign.name}')
    db.session.commit()

    if campaign.mode == 'automated':
        try:
            from app.services.attack_service import AttackExecutor
            executor = AttackExecutor()
            executor.execute_campaign(campaign_id, user_id, 'sequential')
        except Exception as e:
            return jsonify({
                'message': 'Campaign resumed but background execution failed to launch',
                'error': str(e)[:300],
            }), 200

    return jsonify({'message': 'Campaign resumed successfully'})


@api_bp.route('/campaigns/<campaign_id>/complete', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def complete_campaign(campaign_id):
    """Mark a campaign as completed."""
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)

    campaign.status = 'completed'
    campaign.end_date = datetime.utcnow()
    log_action(user_id, 'complete', 'campaign', campaign_id, f'Completed campaign: {campaign.name}')
    db.session.commit()
    return jsonify({'message': 'Campaign marked as completed'})


@api_bp.route('/campaigns/<campaign_id>/run-pending', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def run_pending_executions(campaign_id):
    """Kick off every pending AttackExecution in this campaign.

    Useful for manual-mode campaigns where executions are queued at
    start_campaign() time but never run themselves. Each execution is
    submitted to the AttackExecutor's thread pool and runs in the
    background. Returns the count submitted.
    """
    user_id = get_jwt_identity()
    Campaign.query.get_or_404(campaign_id)

    pending = AttackExecution.query.filter_by(
        campaign_id=campaign_id, status='pending'
    ).all()
    if not pending:
        return jsonify({'message': 'No pending executions',
                        'submitted': 0}), 200

    from app.services.attack_service import AttackExecutor
    executor = AttackExecutor()
    submitted = 0
    errors = []
    for ex in pending:
        attack = Attack.query.get(ex.attack_id)
        target = Target.query.get(ex.target_id)
        if not attack or not target:
            continue
        try:
            cfg = json.loads(attack.default_config) if attack.default_config else {}
        except Exception:
            cfg = {}
        try:
            executor.execute_attack(
                attack.id, target.id, cfg, user_id, campaign_id,
                execution_id=ex.id,
            )
            submitted += 1
        except TypeError:
            # Older AttackExecutor signatures don't accept execution_id —
            # fall back to creating a fresh execution and cancelling the
            # placeholder.
            try:
                executor.execute_attack(attack.id, target.id, cfg, user_id,
                                         campaign_id)
                ex.status = 'cancelled'
                submitted += 1
            except Exception as e:
                errors.append(f'{ex.id}: {e!s:.150}')
        except Exception as e:
            errors.append(f'{ex.id}: {e!s:.150}')

    log_action(user_id, 'run_pending', 'campaign', campaign_id,
               f'Submitted {submitted}/{len(pending)} pending executions')
    db.session.commit()
    return jsonify({
        'message': f'Submitted {submitted} pending executions',
        'submitted': submitted,
        'total_pending': len(pending),
        'errors': errors,
    })


@api_bp.route('/campaigns/<campaign_id>/executions', methods=['GET'])
@jwt_required()
def get_campaign_executions(campaign_id):
    """Get all executions for a campaign"""
    Campaign.query.get_or_404(campaign_id)

    status = request.args.get('status')
    result = request.args.get('result')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    query = AttackExecution.query.filter_by(campaign_id=campaign_id)

    if status:
        query = query.filter(AttackExecution.status == status)
    if result:
        query = query.filter(AttackExecution.result == result)

    pagination = query.order_by(AttackExecution.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    executions = []
    for e in pagination.items:
        attack = Attack.query.get(e.attack_id)
        target = Target.query.get(e.target_id)

        duration = e.duration_seconds
        executions.append({
            'id': e.id,
            'attack': {
                'id': attack.id if attack else None,
                'name': attack.name if attack else 'Unknown'
            },
            'target': {
                'id': target.id if target else None,
                'name': target.name if target else 'Unknown',
                'host': target.host if target else 'Unknown'
            },
            'status': e.status,
            'result': e.result,
            'severity_confirmed': e.severity_found,
            'severity_found': e.severity_found,
            'started_at': e.started_at.isoformat() if e.started_at else None,
            'completed_at': e.completed_at.isoformat() if e.completed_at else None,
            'duration': duration,
            'duration_seconds': duration,
            'duration_ms': int(duration * 1000) if duration else None,
        })

    return jsonify({
        'executions': executions,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@api_bp.route('/campaigns/<campaign_id>/stats', methods=['GET'])
@jwt_required()
def get_campaign_stats(campaign_id):
    """Get summary stats — alias for compatibility with frontend `getStats`."""
    return get_campaign_statistics(campaign_id)


@api_bp.route('/campaigns/<campaign_id>/statistics', methods=['GET'])
@jwt_required()
def get_campaign_statistics(campaign_id):
    """Get detailed statistics for a campaign"""
    campaign = Campaign.query.get_or_404(campaign_id)
    executions = AttackExecution.query.filter_by(campaign_id=campaign_id).all()

    total = len(executions)
    by_status = {}
    by_result = {}
    by_severity = {}
    by_target = {}
    by_attack = {}
    total_duration_seconds = 0

    for e in executions:
        by_status[e.status] = by_status.get(e.status, 0) + 1
        if e.result:
            by_result[e.result] = by_result.get(e.result, 0) + 1
        if e.severity_found:
            by_severity[e.severity_found] = by_severity.get(e.severity_found, 0) + 1

        target = Target.query.get(e.target_id) if e.target_id else None
        if target:
            slot = by_target.setdefault(target.name, {'total': 0, 'vulnerable': 0})
            slot['total'] += 1
            if e.result == 'vulnerable':
                slot['vulnerable'] += 1

        attack = Attack.query.get(e.attack_id) if e.attack_id else None
        if attack:
            slot = by_attack.setdefault(attack.name, {'total': 0, 'vulnerable': 0})
            slot['total'] += 1
            if e.result == 'vulnerable':
                slot['vulnerable'] += 1

        if e.duration_seconds:
            total_duration_seconds += e.duration_seconds

    avg_duration = (total_duration_seconds / total) if total else 0
    return jsonify({
        'campaign_id': campaign_id,
        'campaign_name': campaign.name,
        'total_executions': total,
        'by_status': by_status,
        'by_result': by_result,
        'by_severity': by_severity,
        'by_target': by_target,
        'by_attack': by_attack,
        'average_duration_seconds': avg_duration,
        'average_duration_ms': avg_duration * 1000,
        'progress': campaign.progress,
    })


@api_bp.route('/campaigns/types', methods=['GET'])
@jwt_required()
def get_campaign_types():
    """Get available campaign types"""
    return jsonify({
        'types': [
            {'value': 'external', 'label': 'External Penetration Test'},
            {'value': 'internal', 'label': 'Internal Penetration Test'},
            {'value': 'web', 'label': 'Web Application Test'},
            {'value': 'api', 'label': 'API Security Test'},
            {'value': 'ai_agent', 'label': 'AI Agent Security Test'},
            {'value': 'red_team', 'label': 'Red Team Exercise'},
            {'value': 'purple_team', 'label': 'Purple Team Exercise'}
        ]
    })


@api_bp.route('/campaigns/modes', methods=['GET'])
@jwt_required()
def get_campaign_modes():
    """Get available execution modes"""
    return jsonify({
        'modes': [
            {'value': 'manual', 'label': 'Manual Mode', 'description': 'Execute attacks one by one with manual control'},
            {'value': 'automated', 'label': 'Automated Mode', 'description': 'Execute all attacks automatically'},
            {'value': 'hybrid', 'label': 'Hybrid Mode', 'description': 'Automated with manual approval for critical attacks'}
        ]
    })


@api_bp.route('/campaigns/scenarios', methods=['GET'])
@jwt_required()
def get_campaign_scenarios():
    """Get available attack scenarios"""
    return jsonify({
        'scenarios': [
            {'value': 'direct', 'label': 'Direct Connection', 'description': 'Direct connection to target server'},
            {'value': 'legitimate_client', 'label': 'Legitimate Client', 'description': 'Attack as a legitimate client with valid credentials'},
            {'value': 'mitm', 'label': 'Man-in-the-Middle', 'description': 'Intercept communications between client and server'},
            {'value': 'insider', 'label': 'Insider Threat', 'description': 'Simulate insider with elevated access'},
            {'value': 'supply_chain', 'label': 'Supply Chain', 'description': 'Attack through third-party integrations'}
        ]
    })


@api_bp.route('/campaigns/<campaign_id>/clone', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def clone_campaign(campaign_id):
    """Clone an existing campaign"""
    user_id = get_jwt_identity()
    campaign = Campaign.query.get_or_404(campaign_id)

    new_campaign = Campaign(
        name=f"{campaign.name} (Copy)",
        description=campaign.description,
        campaign_type=campaign.campaign_type,
        mode=campaign.mode,
        scenario=campaign.scenario,
        scope_definition=campaign.scope_definition,
        rules_of_engagement=campaign.rules_of_engagement,
        status='draft',
        owner_id=user_id,
    )
    new_campaign.targets = list(campaign.targets)
    new_campaign.attacks = list(campaign.attacks)

    db.session.add(new_campaign)
    log_action(user_id, 'clone', 'campaign', campaign_id, f'Cloned campaign: {campaign.name}')
    db.session.commit()

    return jsonify({
        'message': 'Campaign cloned successfully',
        'campaign': {
            'id': new_campaign.id,
            'name': new_campaign.name
        }
    }), 201
