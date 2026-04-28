"""
Users API routes
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app.models import User, AuditLog
from app import db
from functools import wraps


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


def manager_or_admin_required(f):
    """Decorator to require manager or admin role"""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role not in ['admin', 'manager']:
            return jsonify({'error': 'Manager or admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


@api_bp.route('/users', methods=['GET'])
@manager_or_admin_required
def get_users():
    """Get all users"""
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200


@api_bp.route('/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get a specific user"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    # Users can view their own profile, managers/admins can view all
    if user_id != current_user_id and current_user.role not in ['admin', 'manager']:
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict()), 200


@api_bp.route('/users', methods=['POST'])
@admin_required
def create_user():
    """Create a new user"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Username, email, and password required'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user = User(
        username=data['username'],
        email=data['email'],
        role=data.get('role', 'operator'),
        is_active=data.get('is_active', True)
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='create',
        resource_type='user',
        resource_id=user.id,
        details='{"username": "' + user.username + '"}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(user.to_dict()), 201


@api_bp.route('/users/<user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """Update a user"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    if data.get('username') and data['username'] != user.username:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400
        user.username = data['username']
    
    if data.get('email') and data['email'] != user.email:
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    
    if data.get('role'):
        user.role = data['role']
    
    if 'is_active' in data:
        user.is_active = data['is_active']
    
    if data.get('password'):
        user.set_password(data['password'])
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='update',
        resource_type='user',
        resource_id=user.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(user.to_dict()), 200


@api_bp.route('/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """Delete a user"""
    current_user_id = get_jwt_identity()
    
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Audit log before deletion
    log = AuditLog(
        user_id=current_user_id,
        action='delete',
        resource_type='user',
        resource_id=user_id,
        details='{"username": "' + user.username + '"}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted'}), 200


@api_bp.route('/users/roles', methods=['GET'])
@jwt_required()
def get_roles():
    """Get available user roles"""
    roles = [
        {'id': 'admin', 'name': 'Administrator', 'description': 'Full system access'},
        {'id': 'manager', 'name': 'Manager', 'description': 'Manage campaigns and users'},
        {'id': 'operator', 'name': 'Operator', 'description': 'Execute attacks and view results'},
        {'id': 'viewer', 'name': 'Viewer', 'description': 'View-only access'}
    ]
    return jsonify(roles), 200
