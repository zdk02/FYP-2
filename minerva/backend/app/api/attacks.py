"""
Attacks API routes
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app.api.users import admin_required, manager_or_admin_required
from app.models import Attack, SubCategory, Payload, Technique, AuditLog
from app import db
import json
import re
import time
import base64
import hashlib


@api_bp.route('/attacks', methods=['GET'])
@jwt_required()
def get_attacks():
    """Get all attacks with filtering"""
    subcategory_id = request.args.get('subcategory_id')
    severity = request.args.get('severity')
    attack_type = request.args.get('attack_type')
    search = request.args.get('search')
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    include_script = request.args.get('include_script', 'false').lower() == 'true'
    
    query = Attack.query
    
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    if subcategory_id:
        query = query.filter_by(subcategory_id=subcategory_id)
    
    if severity:
        query = query.filter_by(severity=severity)
    
    if attack_type:
        query = query.filter_by(attack_type=attack_type)
    
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Attack.name.ilike(search_term),
                Attack.description.ilike(search_term),
                Attack.tags.ilike(search_term)
            )
        )
    
    attacks = query.order_by(Attack.name).all()
    return jsonify([a.to_dict(include_script=include_script) for a in attacks]), 200


@api_bp.route('/attacks/<attack_id>', methods=['GET'])
@jwt_required()
def get_attack(attack_id):
    """Get a specific attack"""
    include_script = request.args.get('include_script', 'true').lower() == 'true'
    
    attack = Attack.query.get(attack_id)
    if not attack:
        return jsonify({'error': 'Attack not found'}), 404
    
    return jsonify(attack.to_dict(include_script=include_script)), 200


@api_bp.route('/attacks', methods=['POST'])
@admin_required
def create_attack():
    """Create a new attack"""
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'Attack name required'}), 400
    
    if not data.get('subcategory_id'):
        return jsonify({'error': 'Subcategory ID required'}), 400
    
    subcategory = SubCategory.query.get(data['subcategory_id'])
    if not subcategory:
        return jsonify({'error': 'Subcategory not found'}), 404
    
    attack = Attack(
        name=data['name'],
        description=data.get('description', ''),
        severity=data.get('severity', 'medium'),
        attack_type=data.get('attack_type'),
        mitre_id=data.get('mitre_id'),
        cve_ids=json.dumps(data.get('cve_ids', [])),
        script_content=data.get('script_content', ''),
        script_language=data.get('script_language', 'python'),
        config_schema=json.dumps(data.get('config_schema', {})),
        default_config=json.dumps(data.get('default_config', {})),
        requires_authentication=data.get('requires_authentication', False),
        timeout=data.get('timeout', 300),
        parallel_safe=data.get('parallel_safe', True),
        author=data.get('author'),
        version=data.get('version', '1.0.0'),
        tags=json.dumps(data.get('tags', [])),
        references=json.dumps(data.get('references', [])),
        is_active=data.get('is_active', True),
        is_verified=data.get('is_verified', False),
        subcategory_id=data['subcategory_id']
    )
    
    # Add payloads if specified
    if data.get('payload_ids'):
        payloads = Payload.query.filter(Payload.id.in_(data['payload_ids'])).all()
        attack.payloads = payloads
    
    # Add techniques if specified
    if data.get('technique_ids'):
        techniques = Technique.query.filter(Technique.id.in_(data['technique_ids'])).all()
        attack.techniques = techniques
    
    db.session.add(attack)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='create',
        resource_type='attack',
        resource_id=attack.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(attack.to_dict(include_script=True)), 201


@api_bp.route('/attacks/<attack_id>', methods=['PUT'])
@admin_required
def update_attack(attack_id):
    """Update an attack"""
    attack = Attack.query.get(attack_id)
    if not attack:
        return jsonify({'error': 'Attack not found'}), 404
    
    data = request.get_json()
    
    # Update basic fields
    if 'name' in data:
        attack.name = data['name']
    if 'description' in data:
        attack.description = data['description']
    if 'severity' in data:
        attack.severity = data['severity']
    if 'attack_type' in data:
        attack.attack_type = data['attack_type']
    if 'mitre_id' in data:
        attack.mitre_id = data['mitre_id']
    if 'cve_ids' in data:
        attack.cve_ids = json.dumps(data['cve_ids'])
    if 'script_content' in data:
        attack.script_content = data['script_content']
    if 'script_language' in data:
        attack.script_language = data['script_language']
    if 'config_schema' in data:
        attack.config_schema = json.dumps(data['config_schema'])
    if 'default_config' in data:
        attack.default_config = json.dumps(data['default_config'])
    if 'requires_authentication' in data:
        attack.requires_authentication = data['requires_authentication']
    if 'timeout' in data:
        attack.timeout = data['timeout']
    if 'parallel_safe' in data:
        attack.parallel_safe = data['parallel_safe']
    if 'author' in data:
        attack.author = data['author']
    if 'version' in data:
        attack.version = data['version']
    if 'tags' in data:
        attack.tags = json.dumps(data['tags'])
    if 'references' in data:
        attack.references = json.dumps(data['references'])
    if 'is_active' in data:
        attack.is_active = data['is_active']
    if 'is_verified' in data:
        attack.is_verified = data['is_verified']
    if 'subcategory_id' in data:
        subcategory = SubCategory.query.get(data['subcategory_id'])
        if subcategory:
            attack.subcategory_id = data['subcategory_id']
    
    # Update payloads
    if 'payload_ids' in data:
        payloads = Payload.query.filter(Payload.id.in_(data['payload_ids'])).all()
        attack.payloads = payloads
    
    # Update techniques
    if 'technique_ids' in data:
        techniques = Technique.query.filter(Technique.id.in_(data['technique_ids'])).all()
        attack.techniques = techniques
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='update',
        resource_type='attack',
        resource_id=attack.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(attack.to_dict(include_script=True)), 200


@api_bp.route('/attacks/<attack_id>', methods=['DELETE'])
@admin_required
def delete_attack(attack_id):
    """Delete an attack"""
    attack = Attack.query.get(attack_id)
    if not attack:
        return jsonify({'error': 'Attack not found'}), 404
    
    # Audit log before deletion
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='delete',
        resource_type='attack',
        resource_id=attack_id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(attack)
    db.session.commit()
    
    return jsonify({'message': 'Attack deleted'}), 200


@api_bp.route('/attacks/<attack_id>/clone', methods=['POST'])
@admin_required
def clone_attack(attack_id):
    """Clone an existing attack"""
    attack = Attack.query.get(attack_id)
    if not attack:
        return jsonify({'error': 'Attack not found'}), 404
    
    data = request.get_json() or {}
    
    new_attack = Attack(
        name=data.get('name', f"{attack.name} (Copy)"),
        description=attack.description,
        severity=attack.severity,
        attack_type=attack.attack_type,
        mitre_id=attack.mitre_id,
        cve_ids=attack.cve_ids,
        script_content=attack.script_content,
        script_language=attack.script_language,
        config_schema=attack.config_schema,
        default_config=attack.default_config,
        requires_authentication=attack.requires_authentication,
        timeout=attack.timeout,
        parallel_safe=attack.parallel_safe,
        author=attack.author,
        version='1.0.0',
        tags=attack.tags,
        references=attack.references,
        is_active=True,
        is_verified=False,
        subcategory_id=data.get('subcategory_id', attack.subcategory_id)
    )
    
    new_attack.payloads = attack.payloads
    new_attack.techniques = attack.techniques
    
    db.session.add(new_attack)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='clone',
        resource_type='attack',
        resource_id=new_attack.id,
        details=json.dumps({'source_id': attack_id}),
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(new_attack.to_dict(include_script=True)), 201


@api_bp.route('/attacks/<attack_id>/verify', methods=['POST'])
@admin_required
def verify_attack(attack_id):
    """Mark an attack as verified"""
    attack = Attack.query.get(attack_id)
    if not attack:
        return jsonify({'error': 'Attack not found'}), 404
    
    attack.is_verified = True
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='verify',
        resource_type='attack',
        resource_id=attack.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(attack.to_dict()), 200


@api_bp.route('/attacks/severities', methods=['GET'])
@jwt_required()
def get_severities():
    """Get available severity levels"""
    severities = [
        {'id': 'critical', 'name': 'Critical', 'color': '#dc2626'},
        {'id': 'high', 'name': 'High', 'color': '#ea580c'},
        {'id': 'medium', 'name': 'Medium', 'color': '#ca8a04'},
        {'id': 'low', 'name': 'Low', 'color': '#16a34a'},
        {'id': 'info', 'name': 'Informational', 'color': '#0284c7'}
    ]
    return jsonify(severities), 200


@api_bp.route('/attacks/types', methods=['GET'])
@jwt_required()
def get_attack_types():
    """Get available attack types"""
    types = [
        {'id': 'injection', 'name': 'Injection'},
        {'id': 'reconnaissance', 'name': 'Reconnaissance'},
        {'id': 'exploitation', 'name': 'Exploitation'},
        {'id': 'privilege_escalation', 'name': 'Privilege Escalation'},
        {'id': 'data_exfiltration', 'name': 'Data Exfiltration'},
        {'id': 'denial_of_service', 'name': 'Denial of Service'},
        {'id': 'manipulation', 'name': 'Manipulation'},
        {'id': 'bypass', 'name': 'Bypass'},
        {'id': 'spoofing', 'name': 'Spoofing'},
        {'id': 'tampering', 'name': 'Tampering'}
    ]
    return jsonify(types), 200


@api_bp.route('/attacks/languages', methods=['GET'])
@jwt_required()
def get_script_languages():
    """Get supported script languages"""
    languages = [
        {'id': 'python', 'name': 'Python', 'extension': '.py'},
        {'id': 'bash', 'name': 'Bash', 'extension': '.sh'},
        {'id': 'ruby', 'name': 'Ruby', 'extension': '.rb'},
        {'id': 'javascript', 'name': 'JavaScript', 'extension': '.js'}
    ]
    return jsonify(languages), 200


@api_bp.route('/attacks/<attack_id>/test', methods=['POST'])
@admin_required
def test_attack(attack_id):
    """Test an attack with provided parameters against a real target"""
    attack = Attack.query.get(attack_id)
    if not attack:
        return jsonify({'error': 'Attack not found'}), 404
    
    data = request.get_json() or {}

    # Get test parameters
    params = data.get('params', {})
    target_config = data.get('target', {
        'host': 'localhost',
        'port': 8080,
        'protocol': 'http',
        'base_url': 'http://localhost:8080'
    })
    dry_run = data.get('dry_run', False)

    # If caller sent a target_id, fully hydrate target_config from DB row.
    # This ensures stdio / SSE / auth'd targets carry their full config
    # (base_url, auth_config, connection_script_id) into the attack runner.
    tid = target_config.get('target_id') or data.get('target_id')
    if tid:
        from app.models import Target as _TargetModel
        _row = _TargetModel.query.get(tid)
        if _row:
            try:
                _auth = json.loads(_row.auth_config) if _row.auth_config else {}
            except Exception:
                _auth = {}
            target_config = {
                'host': _row.host or 'localhost',
                'port': _row.port or 0,
                'protocol': _row.protocol or 'http',
                'base_url': _row.base_url or target_config.get('base_url'),
                'target_type': _row.target_type,
                'auth_config': _auth,
                'target_id': _row.id,
            }

    # Parse default config and merge with provided params
    default_params = {}
    if attack.default_config:
        try:
            default_params = json.loads(attack.default_config)
        except:
            pass
    merged_params = {**default_params, **params}

    # Build base_url if not provided (skip for stdio — base_url is the command)
    if not target_config.get('base_url'):
        proto = target_config.get('protocol', 'http')
        if proto == 'stdio':
            # Cannot auto-build a stdio command — signal the error clearly.
            return jsonify({'error':
                'stdio target needs base_url like "stdio:<command>" — '
                'register via Targets page or send target_id.'}), 400
        target_config['base_url'] = (
            f"{proto}://{target_config.get('host', 'localhost')}"
            f":{target_config.get('port', 8080)}")
    
    result = {
        'attack_id': attack.id,
        'attack_name': attack.name,
        'dry_run': dry_run,
        'target': target_config,
        'parameters_used': merged_params,
        'script_language': attack.script_language,
        'status': 'pending',
        'execution_log': [],
        'findings': [],
        'evidence': []
    }
    
    if dry_run:
        result['status'] = 'validated'
        result['message'] = 'Configuration validated (dry run - no execution)'
        result['execution_log'] = [
            f"[INFO] Attack: {attack.name}",
            f"[INFO] Target: {target_config.get('host')}:{target_config.get('port')}",
            f"[INFO] Parameters: {merged_params}",
            "[INFO] Dry run mode - script not executed"
        ]
    else:
        # Actually execute the attack script
        if not attack.script_content:
            result['status'] = 'error'
            result['message'] = 'No script content defined for this attack'
            result['execution_log'] = ["[ERROR] No script content to execute"]
        else:
            result['execution_log'].append(f"[INFO] Starting attack: {attack.name}")
            result['execution_log'].append(f"[INFO] Target: {target_config.get('host')}:{target_config.get('port')}")
            result['execution_log'].append(f"[INFO] Parameters: {merged_params}")
            
            # Run through the shared attack_runner so /test and campaigns
            # share identical exec semantics + helpers.
            from app.services import attack_runner
            from app.models import Target as _TargetModel

            # Auto-fetch auth_config from matching Target row if caller
            # didn't supply it explicitly.
            if target_config.get('auth_config') is None:
                try:
                    t_row = _TargetModel.query.filter_by(
                        host=target_config.get('host'),
                        port=target_config.get('port'),
                    ).first()
                except Exception:
                    t_row = None
            else:
                t_row = None
            target_config = attack_runner.prepare_target_dict(
                target_config, target_row=t_row)

            result['execution_log'].append("[INFO] Executing attack script...")
            script_result = attack_runner.run_python_attack(
                attack.script_content,
                target=target_config,
                params=merged_params,
                attack_id=attack.id,
                timeout=attack.timeout or 300,
                execution_id='test-' + attack.id[:8],
            )
            result['status'] = 'success' if script_result.get('success') else 'completed'
            result['findings'] = script_result.get('findings', [])
            result['evidence'] = script_result.get('evidence', [])
            result['summary'] = script_result.get('summary', {})
            for log in script_result.get('logs', []):
                result['execution_log'].append(log)
            result['message'] = (
                f"Attack completed — {len(result['findings'])} finding(s)"
            )

            try:
                from app.services import notifier as _notifier
                for _f in result['findings']:
                    _notifier.notify_finding(_f, target=target_config)
            except Exception:
                pass
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='test',
        resource_type='attack',
        resource_id=attack.id,
        details=json.dumps({'dry_run': dry_run, 'target': target_config, 'status': result['status']}),
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(result), 200
