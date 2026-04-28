"""
Categories API routes (Main and Sub categories)
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app.api.users import admin_required
from app.models import MainCategory, SubCategory, AuditLog
from app import db


@api_bp.route('/categories', methods=['GET'])
@jwt_required()
def get_main_categories():
    """Get all main categories"""
    include_subcategories = request.args.get('include_subcategories', 'false').lower() == 'true'
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    
    query = MainCategory.query
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    categories = query.order_by(MainCategory.order).all()
    return jsonify([c.to_dict(include_subcategories=include_subcategories) for c in categories]), 200


@api_bp.route('/categories/<category_id>', methods=['GET'])
@jwt_required()
def get_main_category(category_id):
    """Get a specific main category"""
    category = MainCategory.query.get(category_id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    return jsonify(category.to_dict(include_subcategories=True)), 200


@api_bp.route('/categories', methods=['POST'])
@admin_required
def create_main_category():
    """Create a new main category"""
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'Category name required'}), 400
    
    if MainCategory.query.filter_by(name=data['name']).first():
        return jsonify({'error': 'Category with this name already exists'}), 400
    
    # Get max order
    max_order = db.session.query(db.func.max(MainCategory.order)).scalar() or 0
    
    category = MainCategory(
        name=data['name'],
        description=data.get('description', ''),
        icon=data.get('icon', 'folder'),
        color=data.get('color', '#3b82f6'),
        is_active=data.get('is_active', True),
        order=data.get('order', max_order + 1)
    )
    
    db.session.add(category)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='create',
        resource_type='main_category',
        resource_id=category.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(category.to_dict()), 201


@api_bp.route('/categories/<category_id>', methods=['PUT'])
@admin_required
def update_main_category(category_id):
    """Update a main category"""
    category = MainCategory.query.get(category_id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    
    data = request.get_json()
    
    if data.get('name') and data['name'] != category.name:
        if MainCategory.query.filter_by(name=data['name']).first():
            return jsonify({'error': 'Category with this name already exists'}), 400
        category.name = data['name']
    
    if 'description' in data:
        category.description = data['description']
    if 'icon' in data:
        category.icon = data['icon']
    if 'color' in data:
        category.color = data['color']
    if 'is_active' in data:
        category.is_active = data['is_active']
    if 'order' in data:
        category.order = data['order']
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='update',
        resource_type='main_category',
        resource_id=category.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(category.to_dict()), 200


@api_bp.route('/categories/<category_id>', methods=['DELETE'])
@admin_required
def delete_main_category(category_id):
    """Delete a main category"""
    category = MainCategory.query.get(category_id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    
    # Audit log before deletion
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='delete',
        resource_type='main_category',
        resource_id=category_id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(category)
    db.session.commit()
    
    return jsonify({'message': 'Category deleted'}), 200


# Sub-categories routes

@api_bp.route('/categories/<category_id>/subcategories', methods=['GET'])
@jwt_required()
def get_subcategories(category_id):
    """Get subcategories of a main category"""
    category = MainCategory.query.get(category_id)
    if not category:
        return jsonify({'error': 'Main category not found'}), 404
    
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    include_attacks = request.args.get('include_attacks', 'false').lower() == 'true'
    
    query = SubCategory.query.filter_by(main_category_id=category_id)
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    subcategories = query.order_by(SubCategory.order).all()
    return jsonify([s.to_dict(include_attacks=include_attacks) for s in subcategories]), 200


@api_bp.route('/subcategories/<subcategory_id>', methods=['GET'])
@jwt_required()
def get_subcategory(subcategory_id):
    """Get a specific subcategory"""
    subcategory = SubCategory.query.get(subcategory_id)
    if not subcategory:
        return jsonify({'error': 'Subcategory not found'}), 404
    return jsonify(subcategory.to_dict(include_attacks=True)), 200


@api_bp.route('/categories/<category_id>/subcategories', methods=['POST'])
@admin_required
def create_subcategory(category_id):
    """Create a new subcategory"""
    category = MainCategory.query.get(category_id)
    if not category:
        return jsonify({'error': 'Main category not found'}), 404
    
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'Subcategory name required'}), 400
    
    # Get max order for this main category
    max_order = db.session.query(db.func.max(SubCategory.order)).filter_by(
        main_category_id=category_id
    ).scalar() or 0
    
    subcategory = SubCategory(
        name=data['name'],
        description=data.get('description', ''),
        icon=data.get('icon', 'folder'),
        color=data.get('color', '#3b82f6'),
        is_active=data.get('is_active', True),
        order=data.get('order', max_order + 1),
        main_category_id=category_id
    )
    
    db.session.add(subcategory)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='create',
        resource_type='subcategory',
        resource_id=subcategory.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(subcategory.to_dict()), 201


@api_bp.route('/subcategories/<subcategory_id>', methods=['PUT'])
@admin_required
def update_subcategory(subcategory_id):
    """Update a subcategory"""
    subcategory = SubCategory.query.get(subcategory_id)
    if not subcategory:
        return jsonify({'error': 'Subcategory not found'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        subcategory.name = data['name']
    if 'description' in data:
        subcategory.description = data['description']
    if 'icon' in data:
        subcategory.icon = data['icon']
    if 'color' in data:
        subcategory.color = data['color']
    if 'is_active' in data:
        subcategory.is_active = data['is_active']
    if 'order' in data:
        subcategory.order = data['order']
    if 'main_category_id' in data:
        # Verify new main category exists
        if MainCategory.query.get(data['main_category_id']):
            subcategory.main_category_id = data['main_category_id']
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='update',
        resource_type='subcategory',
        resource_id=subcategory.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(subcategory.to_dict()), 200


@api_bp.route('/subcategories/<subcategory_id>', methods=['DELETE'])
@admin_required
def delete_subcategory(subcategory_id):
    """Delete a subcategory"""
    subcategory = SubCategory.query.get(subcategory_id)
    if not subcategory:
        return jsonify({'error': 'Subcategory not found'}), 404
    
    # Audit log before deletion
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='delete',
        resource_type='subcategory',
        resource_id=subcategory_id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(subcategory)
    db.session.commit()
    
    return jsonify({'message': 'Subcategory deleted'}), 200


@api_bp.route('/categories/reorder', methods=['POST'])
@admin_required
def reorder_categories():
    """Reorder main categories"""
    data = request.get_json()
    
    if not data.get('order'):
        return jsonify({'error': 'Order array required'}), 400
    
    for idx, category_id in enumerate(data['order']):
        category = MainCategory.query.get(category_id)
        if category:
            category.order = idx
    
    db.session.commit()
    return jsonify({'message': 'Categories reordered'}), 200


@api_bp.route('/subcategories/reorder', methods=['POST'])
@admin_required
def reorder_subcategories():
    """Reorder subcategories within a main category"""
    data = request.get_json()
    
    if not data.get('order'):
        return jsonify({'error': 'Order array required'}), 400
    
    for idx, subcategory_id in enumerate(data['order']):
        subcategory = SubCategory.query.get(subcategory_id)
        if subcategory:
            subcategory.order = idx
    
    db.session.commit()
    return jsonify({'message': 'Subcategories reordered'}), 200
