"""
Techniques API routes
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app.api.users import admin_required
from app.models import Technique, AuditLog
from app import db


@api_bp.route('/techniques', methods=['GET'])
@jwt_required()
def get_techniques():
    """Get all techniques"""
    tactic = request.args.get('tactic')
    search = request.args.get('search')
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    
    query = Technique.query
    
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    if tactic:
        query = query.filter_by(tactic=tactic)
    
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Technique.name.ilike(search_term),
                Technique.description.ilike(search_term),
                Technique.mitre_id.ilike(search_term)
            )
        )
    
    techniques = query.order_by(Technique.name).all()
    return jsonify([t.to_dict() for t in techniques]), 200


@api_bp.route('/techniques/<technique_id>', methods=['GET'])
@jwt_required()
def get_technique(technique_id):
    """Get a specific technique"""
    technique = Technique.query.get(technique_id)
    if not technique:
        return jsonify({'error': 'Technique not found'}), 404
    return jsonify(technique.to_dict()), 200


@api_bp.route('/techniques', methods=['POST'])
@admin_required
def create_technique():
    """Create a new technique"""
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'Technique name required'}), 400
    
    technique = Technique(
        name=data['name'],
        description=data.get('description', ''),
        mitre_id=data.get('mitre_id'),
        tactic=data.get('tactic'),
        is_active=data.get('is_active', True)
    )
    
    db.session.add(technique)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='create',
        resource_type='technique',
        resource_id=technique.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(technique.to_dict()), 201


@api_bp.route('/techniques/<technique_id>', methods=['PUT'])
@admin_required
def update_technique(technique_id):
    """Update a technique"""
    technique = Technique.query.get(technique_id)
    if not technique:
        return jsonify({'error': 'Technique not found'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        technique.name = data['name']
    if 'description' in data:
        technique.description = data['description']
    if 'mitre_id' in data:
        technique.mitre_id = data['mitre_id']
    if 'tactic' in data:
        technique.tactic = data['tactic']
    if 'is_active' in data:
        technique.is_active = data['is_active']
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='update',
        resource_type='technique',
        resource_id=technique.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(technique.to_dict()), 200


@api_bp.route('/techniques/<technique_id>', methods=['DELETE'])
@admin_required
def delete_technique(technique_id):
    """Delete a technique"""
    technique = Technique.query.get(technique_id)
    if not technique:
        return jsonify({'error': 'Technique not found'}), 404
    
    # Audit log before deletion
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='delete',
        resource_type='technique',
        resource_id=technique_id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(technique)
    db.session.commit()
    
    return jsonify({'message': 'Technique deleted'}), 200


@api_bp.route('/techniques/tactics', methods=['GET'])
@jwt_required()
def get_tactics():
    """Get MITRE ATT&CK tactics"""
    tactics = [
        {'id': 'reconnaissance', 'name': 'Reconnaissance'},
        {'id': 'resource_development', 'name': 'Resource Development'},
        {'id': 'initial_access', 'name': 'Initial Access'},
        {'id': 'execution', 'name': 'Execution'},
        {'id': 'persistence', 'name': 'Persistence'},
        {'id': 'privilege_escalation', 'name': 'Privilege Escalation'},
        {'id': 'defense_evasion', 'name': 'Defense Evasion'},
        {'id': 'credential_access', 'name': 'Credential Access'},
        {'id': 'discovery', 'name': 'Discovery'},
        {'id': 'lateral_movement', 'name': 'Lateral Movement'},
        {'id': 'collection', 'name': 'Collection'},
        {'id': 'command_and_control', 'name': 'Command and Control'},
        {'id': 'exfiltration', 'name': 'Exfiltration'},
        {'id': 'impact', 'name': 'Impact'}
    ]
    return jsonify(tactics), 200
