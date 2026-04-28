"""
Authentication API routes
"""
from flask import request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from app.api import api_bp
from app.models import User, AuditLog
from app import db
from datetime import datetime
import json


@api_bp.route('/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    # Accept either 'username' or 'email' field
    username_or_email = data.get('username') or data.get('email')
    password = data.get('password')
    
    if not data or not username_or_email or not password:
        return jsonify({'error': 'Username/email and password required'}), 400
    
    # Try to find user by username or email
    user = User.query.filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    ).first()
    
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    # Audit log
    log = AuditLog(
        user_id=user.id,
        action='login',
        resource_type='auth',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:500]
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    }), 200


@api_bp.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': access_token}), 200


@api_bp.route('/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict()), 200


@api_bp.route('/auth/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    data = request.get_json()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not data.get('current_password') or not data.get('new_password'):
        return jsonify({'error': 'Current and new password required'}), 400
    
    if not user.check_password(data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    user.set_password(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'}), 200


@api_bp.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout (client should discard tokens)"""
    current_user_id = get_jwt_identity()
    
    # Audit log
    log = AuditLog(
        user_id=current_user_id,
        action='logout',
        resource_type='auth',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Logged out successfully'}), 200
