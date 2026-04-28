"""
Attack Execution API Routes
Handles individual attack execution and monitoring
"""

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app import db
from app.models.models import (
    AttackExecution, Attack, Target, Campaign, User, AuditLog
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


def _ms(seconds):
    """Convert seconds to milliseconds, tolerating None/zero."""
    if seconds is None:
        return None
    try:
        return int(float(seconds) * 1000)
    except (TypeError, ValueError):
        return None


@api_bp.route('/executions', methods=['GET'])
@jwt_required()
def get_executions():
    """Get all executions with filtering"""
    campaign_id = request.args.get('campaign_id')
    attack_id = request.args.get('attack_id')
    target_id = request.args.get('target_id')
    status = request.args.get('status')
    result = request.args.get('result')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    query = AttackExecution.query

    if campaign_id:
        query = query.filter(AttackExecution.campaign_id == campaign_id)
    if attack_id:
        query = query.filter(AttackExecution.attack_id == attack_id)
    if target_id:
        query = query.filter(AttackExecution.target_id == target_id)
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
        campaign = Campaign.query.get(e.campaign_id) if e.campaign_id else None

        executions.append({
            'id': e.id,
            'campaign': {
                'id': campaign.id,
                'name': campaign.name
            } if campaign else None,
            'attack': {
                'id': attack.id,
                'name': attack.name,
                'severity': attack.severity
            } if attack else None,
            'target': {
                'id': target.id,
                'name': target.name,
                'host': target.host
            } if target else None,
            'status': e.status,
            'result': e.result,
            'severity_confirmed': e.severity_found,
            'severity_found': e.severity_found,
            'started_at': e.started_at.isoformat() if e.started_at else None,
            'completed_at': e.completed_at.isoformat() if e.completed_at else None,
            'duration_seconds': e.duration_seconds,
            'duration_ms': _ms(e.duration_seconds),
        })
    
    return jsonify({
        'executions': executions,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@api_bp.route('/executions/<execution_id>', methods=['GET'])
@jwt_required()
def get_execution(execution_id):
    """Get detailed execution information"""
    execution = AttackExecution.query.get_or_404(execution_id)

    attack = Attack.query.get(execution.attack_id)
    target = Target.query.get(execution.target_id)
    campaign = Campaign.query.get(execution.campaign_id) if execution.campaign_id else None

    return jsonify({
        'id': execution.id,
        'campaign': {
            'id': campaign.id,
            'name': campaign.name
        } if campaign else None,
        'attack': {
            'id': attack.id,
            'name': attack.name,
            'description': attack.description,
            'severity': attack.severity
        } if attack else None,
        'target': {
            'id': target.id,
            'name': target.name,
            'host': target.host,
            'port': target.port
        } if target else None,
        'status': execution.status,
        'result': execution.result,
        'severity_confirmed': execution.severity_found,
        'severity_found': execution.severity_found,
        'output': execution.output,
        'error_message': execution.error_message,
        'evidence': json.loads(execution.evidence) if execution.evidence else {},
        'configuration': json.loads(execution.config_used) if execution.config_used else {},
        'config_used': json.loads(execution.config_used) if execution.config_used else {},
        'notes': execution.notes,
        'executed_by': execution.executed_by,
        'started_at': execution.started_at.isoformat() if execution.started_at else None,
        'completed_at': execution.completed_at.isoformat() if execution.completed_at else None,
        'duration_seconds': execution.duration_seconds,
        'duration_ms': _ms(execution.duration_seconds),
        'created_at': execution.created_at.isoformat()
    })


@api_bp.route('/executions', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def create_execution():
    """Create and optionally run a standalone execution (manual mode)"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data.get('attack_id'):
        return jsonify({'error': 'Attack ID is required'}), 400
    if not data.get('target_id'):
        return jsonify({'error': 'Target ID is required'}), 400
    
    # Verify attack and target exist
    attack = Attack.query.get(data['attack_id'])
    target = Target.query.get(data['target_id'])
    
    if not attack:
        return jsonify({'error': 'Attack not found'}), 404
    if not target:
        return jsonify({'error': 'Target not found'}), 404
    
    execution = AttackExecution(
        campaign_id=data.get('campaign_id'),
        attack_id=data['attack_id'],
        target_id=data['target_id'],
        status='pending',
        config_used=json.dumps(data.get('configuration', {})),
        notes=data.get('notes'),
        executed_by=user_id
    )

    db.session.add(execution)
    log_action(user_id, 'create', 'execution',
               details=f'Created execution: {attack.name} -> {target.name}')
    db.session.commit()

    # Auto-run if specified
    if data.get('auto_run', False):
        return run_execution(execution.id)

    return jsonify({
        'message': 'Execution created successfully',
        'execution': {
            'id': execution.id,
            'status': execution.status
        }
    }), 201


@api_bp.route('/executions/<execution_id>/run', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def run_execution(execution_id):
    """Run a pending execution"""
    user_id = get_jwt_identity()
    execution = AttackExecution.query.get_or_404(execution_id)

    if execution.status not in ['pending', 'cancelled']:
        return jsonify({'error': f'Cannot run execution with status: {execution.status}'}), 400

    attack = Attack.query.get(execution.attack_id)
    target = Target.query.get(execution.target_id)

    if not attack or not attack.script_content:
        return jsonify({'error': 'Attack script not found'}), 404
    if not target:
        return jsonify({'error': 'Target not found'}), 404

    # Update status
    execution.status = 'running'
    execution.started_at = datetime.utcnow()
    db.session.commit()

    # Execute the attack
    from app.services.attack_service import AttackExecutor
    executor = AttackExecutor()

    try:
        result = executor.execute_attack(
            attack_id=attack.id,
            target_id=target.id,
            execution_id=execution.id,
            config=json.loads(execution.config_used) if execution.config_used else {}
        )

        # Update execution with results
        execution.status = 'completed'
        execution.result = result.get('result', 'inconclusive')
        execution.output = (result.get('output') or '')[:10000]  # Limit output size
        execution.evidence = json.dumps(result.get('evidence', {}))
        execution.severity_found = result.get('severity_confirmed') or result.get('severity_found')
        execution.completed_at = datetime.utcnow()
        if execution.started_at:
            execution.duration_seconds = int((execution.completed_at - execution.started_at).total_seconds())

    except Exception as e:
        execution.status = 'error'
        execution.result = 'error'
        execution.error_message = str(e)[:2000]
        execution.completed_at = datetime.utcnow()

    log_action(user_id, 'run', 'execution', execution_id,
               f'Ran execution: {attack.name} -> {target.name}, result: {execution.result}')
    db.session.commit()

    # Update campaign progress if part of a campaign
    if execution.campaign_id:
        update_campaign_progress(execution.campaign_id)

    return jsonify({
        'message': 'Execution completed',
        'execution': {
            'id': execution.id,
            'status': execution.status,
            'result': execution.result,
            'duration_seconds': execution.duration_seconds,
            'duration_ms': _ms(execution.duration_seconds),
        }
    })


@api_bp.route('/executions/<execution_id>/cancel', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def cancel_execution(execution_id):
    """Cancel a pending execution"""
    user_id = get_jwt_identity()
    execution = AttackExecution.query.get_or_404(execution_id)
    
    if execution.status != 'pending':
        return jsonify({'error': 'Can only cancel pending executions'}), 400
    
    execution.status = 'cancelled'
    log_action(user_id, 'cancel', 'execution', execution_id, 'Cancelled execution')
    db.session.commit()
    
    return jsonify({'message': 'Execution cancelled'})


@api_bp.route('/executions/<execution_id>/retry', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def retry_execution(execution_id):
    """Retry a failed or error execution"""
    user_id = get_jwt_identity()
    execution = AttackExecution.query.get_or_404(execution_id)

    if execution.status not in ['error', 'completed']:
        return jsonify({'error': 'Can only retry completed or error executions'}), 400

    # Create a new execution based on this one
    new_execution = AttackExecution(
        campaign_id=execution.campaign_id,
        attack_id=execution.attack_id,
        target_id=execution.target_id,
        status='pending',
        config_used=execution.config_used,
        notes=f'Retry of execution #{execution_id}',
        executed_by=user_id
    )
    
    db.session.add(new_execution)
    log_action(user_id, 'retry', 'execution', execution_id, 'Created retry execution')
    db.session.commit()
    
    return jsonify({
        'message': 'Retry execution created',
        'execution': {
            'id': new_execution.id,
            'status': new_execution.status
        }
    })


@api_bp.route('/executions/<execution_id>/notes', methods=['PUT'])
@jwt_required()
def update_execution_notes(execution_id):
    """Update notes for an execution"""
    user_id = get_jwt_identity()
    execution = AttackExecution.query.get_or_404(execution_id)
    data = request.get_json()
    
    execution.notes = data.get('notes', '')
    log_action(user_id, 'update', 'execution', execution_id, 'Updated execution notes')
    db.session.commit()
    
    return jsonify({'message': 'Notes updated successfully'})


@api_bp.route('/executions/<execution_id>/severity', methods=['PUT'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def update_execution_severity(execution_id):
    """Manually update confirmed severity for an execution"""
    user_id = get_jwt_identity()
    execution = AttackExecution.query.get_or_404(execution_id)
    data = request.get_json()

    if data.get('severity') not in ['critical', 'high', 'medium', 'low', 'info', None]:
        return jsonify({'error': 'Invalid severity level'}), 400

    execution.severity_found = data.get('severity')
    log_action(user_id, 'update', 'execution', execution_id,
               f'Updated severity to: {execution.severity_found}')
    db.session.commit()

    return jsonify({'message': 'Severity updated successfully'})


@api_bp.route('/executions/batch', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def batch_run_executions():
    """Run multiple executions"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    execution_ids = data.get('execution_ids', [])
    if not execution_ids:
        return jsonify({'error': 'No execution IDs provided'}), 400
    
    results = []
    for exec_id in execution_ids:
        execution = AttackExecution.query.get(exec_id)
        if not execution:
            results.append({'id': exec_id, 'error': 'Not found'})
            continue
        if execution.status != 'pending':
            results.append({'id': exec_id, 'error': f'Invalid status: {execution.status}'})
            continue
        
        # Run execution
        response = run_execution(exec_id)
        results.append({'id': exec_id, 'success': True})
    
    return jsonify({
        'message': f'Batch execution completed',
        'results': results
    })


@api_bp.route('/executions/quick-run', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def quick_run():
    """Quickly execute an attack against a target (create + run in one call)"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data.get('attack_id'):
        return jsonify({'error': 'Attack ID is required'}), 400
    if not data.get('target_id'):
        return jsonify({'error': 'Target ID is required'}), 400
    
    # Create execution with auto_run
    data['auto_run'] = True
    return create_execution()


def update_campaign_progress(campaign_id):
    """Update campaign progress based on completed executions"""
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return
    
    total = AttackExecution.query.filter_by(campaign_id=campaign_id).count()
    completed = AttackExecution.query.filter(
        AttackExecution.campaign_id == campaign_id,
        AttackExecution.status.in_(['completed', 'error', 'cancelled'])
    ).count()
    
    if total > 0:
        campaign.progress = int((completed / total) * 100)
    
    # Check if campaign is complete
    if completed == total and total > 0:
        campaign.status = 'completed'
        campaign.end_date = datetime.utcnow()
    
    db.session.commit()


@api_bp.route('/executions/statuses', methods=['GET'])
@jwt_required()
def get_execution_statuses():
    """Get available execution statuses"""
    return jsonify({
        'statuses': [
            {'value': 'pending', 'label': 'Pending', 'color': 'gray'},
            {'value': 'running', 'label': 'Running', 'color': 'blue'},
            {'value': 'completed', 'label': 'Completed', 'color': 'green'},
            {'value': 'error', 'label': 'Error', 'color': 'red'},
            {'value': 'cancelled', 'label': 'Cancelled', 'color': 'orange'}
        ]
    })


@api_bp.route('/executions/results', methods=['GET'])
@jwt_required()
def get_execution_results():
    """Get available execution result types"""
    return jsonify({
        'results': [
            {'value': 'vulnerable', 'label': 'Vulnerable', 'color': 'red'},
            {'value': 'not_vulnerable', 'label': 'Not Vulnerable', 'color': 'green'},
            {'value': 'inconclusive', 'label': 'Inconclusive', 'color': 'yellow'},
            {'value': 'error', 'label': 'Error', 'color': 'gray'}
        ]
    })
