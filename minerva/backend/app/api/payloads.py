"""
Payloads API routes
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app.api.users import admin_required
from app.models import Payload, AuditLog
from app import db
import json


@api_bp.route('/payloads', methods=['GET'])
@jwt_required()
def get_payloads():
    """Get all payloads"""
    payload_type = request.args.get('type')
    search = request.args.get('search')
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    
    query = Payload.query
    
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    if payload_type:
        query = query.filter_by(payload_type=payload_type)
    
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Payload.name.ilike(search_term),
                Payload.description.ilike(search_term),
                Payload.content.ilike(search_term)
            )
        )
    
    payloads = query.order_by(Payload.name).all()
    return jsonify([p.to_dict() for p in payloads]), 200


@api_bp.route('/payloads/<payload_id>', methods=['GET'])
@jwt_required()
def get_payload(payload_id):
    """Get a specific payload"""
    payload = Payload.query.get(payload_id)
    if not payload:
        return jsonify({'error': 'Payload not found'}), 404
    return jsonify(payload.to_dict()), 200


@api_bp.route('/payloads', methods=['POST'])
@admin_required
def create_payload():
    """Create a new payload"""
    data = request.get_json()
    
    if not data.get('name') or not data.get('content'):
        return jsonify({'error': 'Name and content required'}), 400
    
    payload = Payload(
        name=data['name'],
        description=data.get('description', ''),
        payload_type=data.get('payload_type'),
        content=data['content'],
        encoding=data.get('encoding'),
        is_active=data.get('is_active', True),
        tags=json.dumps(data.get('tags', []))
    )
    
    db.session.add(payload)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='create',
        resource_type='payload',
        resource_id=payload.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(payload.to_dict()), 201


@api_bp.route('/payloads/<payload_id>', methods=['PUT'])
@admin_required
def update_payload(payload_id):
    """Update a payload"""
    payload = Payload.query.get(payload_id)
    if not payload:
        return jsonify({'error': 'Payload not found'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        payload.name = data['name']
    if 'description' in data:
        payload.description = data['description']
    if 'payload_type' in data:
        payload.payload_type = data['payload_type']
    if 'content' in data:
        payload.content = data['content']
    if 'encoding' in data:
        payload.encoding = data['encoding']
    if 'is_active' in data:
        payload.is_active = data['is_active']
    if 'tags' in data:
        payload.tags = json.dumps(data['tags'])
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='update',
        resource_type='payload',
        resource_id=payload.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(payload.to_dict()), 200


@api_bp.route('/payloads/<payload_id>', methods=['DELETE'])
@admin_required
def delete_payload(payload_id):
    """Delete a payload"""
    payload = Payload.query.get(payload_id)
    if not payload:
        return jsonify({'error': 'Payload not found'}), 404
    
    # Audit log before deletion
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='delete',
        resource_type='payload',
        resource_id=payload_id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(payload)
    db.session.commit()
    
    return jsonify({'message': 'Payload deleted'}), 200


@api_bp.route('/payloads/types', methods=['GET'])
@jwt_required()
def get_payload_types():
    """Get available payload types"""
    types = [
        {'id': 'injection', 'name': 'Injection'},
        {'id': 'malformed_input', 'name': 'Malformed Input'},
        {'id': 'overflow', 'name': 'Buffer Overflow'},
        {'id': 'encoding_bypass', 'name': 'Encoding Bypass'},
        {'id': 'prompt_injection', 'name': 'Prompt Injection'},
        {'id': 'jailbreak', 'name': 'Jailbreak'},
        {'id': 'data_extraction', 'name': 'Data Extraction'},
        {'id': 'command_injection', 'name': 'Command Injection'},
        {'id': 'path_traversal', 'name': 'Path Traversal'},
        {'id': 'xxe', 'name': 'XXE'},
        {'id': 'ssrf', 'name': 'SSRF'}
    ]
    return jsonify(types), 200
