"""
Settings Management API Routes
Handles system settings and configuration
"""

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app import db
from app.models.models import SystemSettings, User, AuditLog
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


@api_bp.route('/settings', methods=['GET'])
@jwt_required()
def get_settings():
    """Get all system settings"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Non-admin users only see public settings
    if user.role == 'admin':
        settings = SystemSettings.query.all()
    else:
        settings = SystemSettings.query.filter_by(is_secret=False).all()
    
    result = {}
    for s in settings:
        # Parse value based on type
        if s.value_type == 'json':
            try:
                result[s.key] = {
                    'value': json.loads(s.value),
                    'type': s.value_type,
                    'description': s.description,
                    'category': s.category
                }
            except:
                result[s.key] = {
                    'value': s.value,
                    'type': 'string',
                    'description': s.description,
                    'category': s.category
                }
        elif s.value_type == 'integer':
            result[s.key] = {
                'value': int(s.value) if s.value else 0,
                'type': s.value_type,
                'description': s.description,
                'category': s.category
            }
        elif s.value_type == 'boolean':
            result[s.key] = {
                'value': s.value.lower() in ('true', '1', 'yes'),
                'type': s.value_type,
                'description': s.description,
                'category': s.category
            }
        else:
            result[s.key] = {
                'value': s.value if not s.is_secret else '********',
                'type': s.value_type,
                'description': s.description,
                'category': s.category
            }
    
    return jsonify({'settings': result})


@api_bp.route('/settings/<key>', methods=['GET'])
@jwt_required()
def get_setting(key):
    """Get a specific setting"""
    setting = SystemSettings.query.filter_by(key=key).first()
    
    if not setting:
        return jsonify({'error': 'Setting not found'}), 404
    
    if setting.is_secret:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403
    
    # Parse value
    value = setting.value
    if setting.value_type == 'json':
        try:
            value = json.loads(setting.value)
        except:
            pass
    elif setting.value_type == 'integer':
        value = int(setting.value) if setting.value else 0
    elif setting.value_type == 'boolean':
        value = setting.value.lower() in ('true', '1', 'yes')
    
    return jsonify({
        'key': setting.key,
        'value': value if not setting.is_secret else '********',
        'type': setting.value_type,
        'description': setting.description,
        'category': setting.category,
        'updated_at': setting.updated_at.isoformat() if setting.updated_at else None
    })


@api_bp.route('/settings/<key>', methods=['PUT'])
@jwt_required()
@require_role('admin')
def update_setting(key):
    """Update a setting"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    setting = SystemSettings.query.filter_by(key=key).first()
    
    if not setting:
        return jsonify({'error': 'Setting not found'}), 404
    
    # Convert value to string for storage
    value = data.get('value')
    if setting.value_type == 'json':
        value = json.dumps(value)
    elif setting.value_type == 'boolean':
        value = 'true' if value else 'false'
    else:
        value = str(value)
    
    old_value = setting.value if not setting.is_secret else '[SECRET]'
    setting.value = value
    setting.updated_at = datetime.utcnow()
    setting.updated_by = user_id
    
    log_action(user_id, 'update', 'setting', 
               details=f'Updated setting {key}: {old_value} -> {value if not setting.is_secret else "[SECRET]"}')
    db.session.commit()
    
    return jsonify({'message': 'Setting updated successfully'})


@api_bp.route('/settings', methods=['POST'])
@jwt_required()
@require_role('admin')
def create_setting():
    """Create a new setting"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data.get('key'):
        return jsonify({'error': 'Setting key is required'}), 400
    
    # Check if setting already exists
    existing = SystemSettings.query.filter_by(key=data['key']).first()
    if existing:
        return jsonify({'error': 'Setting already exists'}), 409
    
    # Convert value to string
    value = data.get('value', '')
    value_type = data.get('type', 'string')
    
    if value_type == 'json':
        value = json.dumps(value)
    elif value_type == 'boolean':
        value = 'true' if value else 'false'
    else:
        value = str(value)
    
    setting = SystemSettings(
        key=data['key'],
        value=value,
        value_type=value_type,
        description=data.get('description'),
        category=data.get('category', 'general'),
        is_secret=data.get('is_secret', False),
        updated_by=user_id
    )
    
    db.session.add(setting)
    log_action(user_id, 'create', 'setting', details=f'Created setting: {data["key"]}')
    db.session.commit()
    
    return jsonify({
        'message': 'Setting created successfully',
        'setting': {'key': setting.key}
    }), 201


@api_bp.route('/settings/<key>', methods=['DELETE'])
@jwt_required()
@require_role('admin')
def delete_setting(key):
    """Delete a setting"""
    user_id = get_jwt_identity()
    setting = SystemSettings.query.filter_by(key=key).first()
    
    if not setting:
        return jsonify({'error': 'Setting not found'}), 404
    
    db.session.delete(setting)
    log_action(user_id, 'delete', 'setting', details=f'Deleted setting: {key}')
    db.session.commit()
    
    return jsonify({'message': 'Setting deleted successfully'})


@api_bp.route('/settings/categories', methods=['GET'])
@jwt_required()
def get_setting_categories():
    """Get available setting categories"""
    return jsonify({
        'categories': [
            {'value': 'general', 'label': 'General'},
            {'value': 'security', 'label': 'Security'},
            {'value': 'execution', 'label': 'Execution'},
            {'value': 'scanning', 'label': 'Scanning'},
            {'value': 'reporting', 'label': 'Reporting'},
            {'value': 'notifications', 'label': 'Notifications'},
            {'value': 'integration', 'label': 'Integrations'}
        ]
    })


@api_bp.route('/settings/bulk', methods=['PUT'])
@jwt_required()
@require_role('admin')
def bulk_update_settings():
    """Update multiple settings at once"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    settings = data.get('settings', {})
    if not settings:
        return jsonify({'error': 'No settings provided'}), 400
    
    updated = 0
    errors = []
    
    for key, value in settings.items():
        setting = SystemSettings.query.filter_by(key=key).first()
        if not setting:
            errors.append(f'{key}: Not found')
            continue
        
        try:
            if setting.value_type == 'json':
                setting.value = json.dumps(value)
            elif setting.value_type == 'boolean':
                setting.value = 'true' if value else 'false'
            else:
                setting.value = str(value)
            
            setting.updated_at = datetime.utcnow()
            setting.updated_by = user_id
            updated += 1
        except Exception as e:
            errors.append(f'{key}: {str(e)}')
    
    log_action(user_id, 'bulk_update', 'settings', details=f'Updated {updated} settings')
    db.session.commit()
    
    return jsonify({
        'message': f'Updated {updated} settings',
        'updated': updated,
        'errors': errors
    })


@api_bp.route('/settings/export', methods=['GET'])
@jwt_required()
@require_role('admin')
def export_settings():
    """Export all settings (excluding secrets)"""
    settings = SystemSettings.query.filter_by(is_secret=False).all()
    
    export_data = {}
    for s in settings:
        value = s.value
        if s.value_type == 'json':
            try:
                value = json.loads(s.value)
            except:
                pass
        elif s.value_type == 'integer':
            value = int(s.value) if s.value else 0
        elif s.value_type == 'boolean':
            value = s.value.lower() in ('true', '1', 'yes')
        
        export_data[s.key] = {
            'value': value,
            'type': s.value_type,
            'description': s.description,
            'category': s.category
        }
    
    return jsonify({
        'exported_at': datetime.utcnow().isoformat(),
        'settings': export_data
    })


@api_bp.route('/settings/import', methods=['POST'])
@jwt_required()
@require_role('admin')
def import_settings():
    """Import settings from JSON"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    settings = data.get('settings', {})
    if not settings:
        return jsonify({'error': 'No settings provided'}), 400
    
    created = 0
    updated = 0
    errors = []
    
    for key, setting_data in settings.items():
        try:
            value = setting_data.get('value', '')
            value_type = setting_data.get('type', 'string')
            
            if value_type == 'json':
                value = json.dumps(value)
            elif value_type == 'boolean':
                value = 'true' if value else 'false'
            else:
                value = str(value)
            
            existing = SystemSettings.query.filter_by(key=key).first()
            
            if existing:
                existing.value = value
                existing.value_type = value_type
                existing.description = setting_data.get('description', existing.description)
                existing.category = setting_data.get('category', existing.category)
                existing.updated_at = datetime.utcnow()
                existing.updated_by = user_id
                updated += 1
            else:
                new_setting = SystemSettings(
                    key=key,
                    value=value,
                    value_type=value_type,
                    description=setting_data.get('description'),
                    category=setting_data.get('category', 'general'),
                    updated_by=user_id
                )
                db.session.add(new_setting)
                created += 1
                
        except Exception as e:
            errors.append(f'{key}: {str(e)}')
    
    log_action(user_id, 'import', 'settings', details=f'Imported {created} new, {updated} updated')
    db.session.commit()
    
    return jsonify({
        'message': f'Imported settings: {created} created, {updated} updated',
        'created': created,
        'updated': updated,
        'errors': errors
    })


@api_bp.route('/settings/reset', methods=['POST'])
@jwt_required()
@require_role('admin')
def reset_settings():
    """Reset settings to defaults"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    category = data.get('category')
    
    if category:
        # Reset only settings in specific category
        SystemSettings.query.filter_by(category=category).delete()
    else:
        # Reset all non-secret settings
        SystemSettings.query.filter_by(is_secret=False).delete()
    
    # Reinitialize defaults
    from app.services.init_service import initialize_default_data
    initialize_default_data()
    
    log_action(user_id, 'reset', 'settings', 
               details=f'Reset settings{" in category: " + category if category else ""}')
    db.session.commit()
    
    return jsonify({'message': 'Settings reset to defaults'})


@api_bp.route('/audit-logs', methods=['GET'])
@jwt_required()
@require_role('admin', 'manager')
def get_audit_logs():
    """Get audit logs with filtering"""
    user_id_filter = request.args.get('user_id', type=int)
    action = request.args.get('action')
    entity_type = request.args.get('entity_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    query = AuditLog.query
    
    if user_id_filter:
        query = query.filter(AuditLog.user_id == user_id_filter)
    if action:
        query = query.filter(AuditLog.action == action)
    if entity_type:
        query = query.filter(AuditLog.resource_type == entity_type)
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)
    
    pagination = query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    logs = []
    for log in pagination.items:
        user = User.query.get(log.user_id) if log.user_id else None
        logs.append({
            'id': log.id,
            'user': {
                'id': user.id,
                'username': user.username
            } if user else None,
            'action': log.action,
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'details': log.details,
            'ip_address': log.ip_address,
            'created_at': log.created_at.isoformat()
        })
    
    return jsonify({
        'logs': logs,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@api_bp.route('/audit-logs/actions', methods=['GET'])
@jwt_required()
@require_role('admin', 'manager')
def get_audit_actions():
    """Get distinct audit log actions"""
    actions = db.session.query(AuditLog.action).distinct().all()
    return jsonify({
        'actions': [a[0] for a in actions if a[0]]
    })


@api_bp.route('/audit-logs/entity-types', methods=['GET'])
@jwt_required()
@require_role('admin', 'manager')
def get_audit_entity_types():
    """Get distinct audit log entity types"""
    types = db.session.query(AuditLog.resource_type).distinct().all()
    return jsonify({
        'entity_types': [t[0] for t in types if t[0]]
    })
