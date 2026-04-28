"""
Target Management API Routes
Handles CRUD operations for penetration testing targets
"""

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app import db
from app.models.models import Target, DiscoveredEndpoint, User, AuditLog
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
    """Create an audit log entry (maps frontend 'entity_*' -> model 'resource_*')."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=entity_type,
        resource_id=entity_id,
        details=details if isinstance(details, str) else (
            None if details is None else str(details)
        ),
        ip_address=request.remote_addr,
        user_agent=(request.headers.get('User-Agent') or '')[:500],
    )
    db.session.add(log)


@api_bp.route('/targets', methods=['GET'])
@jwt_required()
def get_targets():
    """Get all targets with optional filtering"""
    try:
        # Query parameters
        target_type = request.args.get('type') or request.args.get('target_type')
        environment = request.args.get('environment')
        status = request.args.get('status')
        search = request.args.get('search')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        limit = request.args.get('limit', type=int)
        
        query = Target.query
        
        if target_type:
            query = query.filter(Target.target_type == target_type)
        if environment:
            query = query.filter(Target.environment == environment)
        if status:
            # Map status to is_active
            if status == 'active':
                query = query.filter(Target.is_active == True)
            elif status == 'inactive':
                query = query.filter(Target.is_active == False)
        if search:
            query = query.filter(
                db.or_(
                    Target.name.ilike(f'%{search}%'),
                    Target.host.ilike(f'%{search}%'),
                    Target.description.ilike(f'%{search}%')
                )
            )
        
        def serialize_target(t):
            """Safely serialize a target"""
            tags = []
            try:
                if t.tags:
                    tags = json.loads(t.tags)
            except:
                pass
            
            try:
                auth_cfg = json.loads(t.auth_config) if t.auth_config else {}
            except Exception:
                auth_cfg = {}
            return {
                'id': t.id,
                'name': t.name,
                'target_type': t.target_type,
                'host': t.host,
                'port': t.port,
                'protocol': t.protocol,
                'base_url': t.base_url,
                'auth_type': t.auth_type,
                'auth_config': auth_cfg,
                'environment': t.environment,
                'status': 'active' if t.is_active else 'inactive',
                'is_active': t.is_active if t.is_active is not None else True,
                'description': t.description,
                'notes': t.notes,
                'tags': tags,
                'connection_script_id': t.connection_script_id,
                'created_at': t.created_at.isoformat() if t.created_at else None,
                'updated_at': t.updated_at.isoformat() if t.updated_at else None
            }
        
        # If limit is set, don't paginate
        if limit:
            targets_list = query.order_by(Target.created_at.desc()).limit(limit).all()
            targets = [serialize_target(t) for t in targets_list]
            return jsonify({
                'targets': targets,
                'total': len(targets)
            })
        
        pagination = query.order_by(Target.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        targets = [serialize_target(t) for t in pagination.items]
        
        return jsonify({
            'targets': targets,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
    except Exception as e:
        return jsonify({'error': f'Failed to fetch targets: {str(e)}'}), 500


@api_bp.route('/targets/<target_id>', methods=['GET'])
@jwt_required()
def get_target(target_id):
    """Get a specific target with all details"""
    target = Target.query.get_or_404(target_id)
    
    return jsonify({
        'id': target.id,
        'name': target.name,
        'target_type': target.target_type,
        'host': target.host,
        'port': target.port,
        'protocol': target.protocol,
        'base_url': target.base_url,
        'environment': target.environment,
        'status': 'active' if target.is_active else 'inactive',
        'is_active': target.is_active,
        'description': target.description,
        'notes': target.notes,
        'tags': json.loads(target.tags) if target.tags else [],
        'auth_config': json.loads(target.auth_config) if target.auth_config else {},
        'connection_script_id': target.connection_script_id,
        'custom_config': json.loads(target.custom_config) if target.custom_config else {},
        'discovered_endpoints': [{
            'id': e.id,
            'endpoint_type': e.endpoint_type,
            'path': e.path,
            'method': e.method,
            'service_info': json.loads(e.service_info) if e.service_info else {},
            'discovered_at': e.discovered_at.isoformat()
        } for e in target.discovered_endpoints],
        'created_at': target.created_at.isoformat(),
        'updated_at': target.updated_at.isoformat() if target.updated_at else None
    })


@api_bp.route('/targets', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def create_target():
    """Create a new target"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    # Validate required fields
    if not data.get('name'):
        return jsonify({'error': 'Target name is required'}), 400
    protocol = (data.get('protocol') or 'http').lower()
    # stdio targets use a spawn command in base_url; host/port are irrelevant
    if protocol == 'stdio':
        if not data.get('base_url'):
            return jsonify({'error':
                'stdio targets require base_url as "stdio:<command>"'}), 400
    else:
        if not data.get('host'):
            return jsonify({'error': 'Target host is required'}), 400

    # Convert port to int if provided
    port = data.get('port')
    if port:
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = None

    target = Target(
        name=data['name'],
        target_type=data.get('target_type', 'mcp_server'),
        host=data.get('host') or 'localhost',
        port=port,
        protocol=protocol,
        base_url=data.get('base_url'),
        environment=data.get('environment', 'production'),
        is_active=data.get('status', 'active') == 'active',
        description=data.get('description'),
        notes=data.get('notes'),
        tags=json.dumps(data.get('tags', [])) if data.get('tags') else None,
        auth_config=json.dumps(data.get('auth_config', {})) if data.get('auth_config') else None,
        connection_script_id=data.get('connection_script_id'),
        custom_config=json.dumps(data.get('custom_config', {})) if data.get('custom_config') else None
    )
    
    db.session.add(target)
    log_action(user_id, 'create', 'target', details=f'Created target: {target.name}')
    db.session.commit()
    
    return jsonify({
        'message': 'Target created successfully',
        'target': {
            'id': target.id,
            'name': target.name,
            'host': target.host,
            'port': target.port
        }
    }), 201


@api_bp.route('/targets/<target_id>', methods=['PUT'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def update_target(target_id):
    """Update an existing target"""
    user_id = get_jwt_identity()
    target = Target.query.get_or_404(target_id)
    data = request.get_json()
    
    # Update fields
    if 'name' in data:
        target.name = data['name']
    if 'target_type' in data:
        target.target_type = data['target_type']
    if 'host' in data:
        target.host = data['host']
    if 'port' in data:
        try:
            target.port = int(data['port']) if data['port'] else None
        except (ValueError, TypeError):
            target.port = None
    if 'protocol' in data:
        target.protocol = data['protocol']
    if 'base_url' in data:
        target.base_url = data['base_url']
    if 'environment' in data:
        target.environment = data['environment']
    if 'status' in data:
        target.is_active = data['status'] == 'active'
    if 'is_active' in data:
        target.is_active = data['is_active']
    if 'description' in data:
        target.description = data['description']
    if 'notes' in data:
        target.notes = data['notes']
    if 'tags' in data:
        target.tags = json.dumps(data['tags']) if data['tags'] else None
    if 'auth_config' in data:
        target.auth_config = json.dumps(data['auth_config']) if data['auth_config'] else None
    if 'connection_script_id' in data:
        target.connection_script_id = data['connection_script_id']
    if 'custom_config' in data:
        target.custom_config = json.dumps(data['custom_config']) if data['custom_config'] else None
    
    target.updated_at = datetime.utcnow()
    log_action(user_id, 'update', 'target', target_id, f'Updated target: {target.name}')
    db.session.commit()
    
    return jsonify({'message': 'Target updated successfully'})


@api_bp.route('/targets/<target_id>', methods=['DELETE'])
@jwt_required()
@require_role('admin', 'manager')
def delete_target(target_id):
    """Delete a target"""
    user_id = get_jwt_identity()
    target = Target.query.get_or_404(target_id)
    
    target_name = target.name
    db.session.delete(target)
    log_action(user_id, 'delete', 'target', target_id, f'Deleted target: {target_name}')
    db.session.commit()
    
    return jsonify({'message': 'Target deleted successfully'})


@api_bp.route('/targets/<target_id>/endpoints', methods=['GET'])
@jwt_required()
def get_target_endpoints(target_id):
    """Get discovered endpoints for a target"""
    target = Target.query.get_or_404(target_id)

    endpoints = [{
        'id': e.id,
        'path': e.endpoint_path,
        'endpoint_path': e.endpoint_path,
        'method': e.method,
        'description': e.description,
        'parameters': json.loads(e.parameters) if e.parameters else {},
        'response_schema': json.loads(e.response_schema) if e.response_schema else {},
        'is_vulnerable': e.is_vulnerable,
        'vulnerability_notes': e.vulnerability_notes,
        'discovered_at': e.discovered_at.isoformat() if e.discovered_at else None,
    } for e in target.discovered_endpoints]

    return jsonify({'endpoints': endpoints})


@api_bp.route('/targets/<target_id>/endpoints', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def add_endpoint(target_id):
    """Manually add an endpoint to a target"""
    user_id = get_jwt_identity()
    target = Target.query.get_or_404(target_id)
    data = request.get_json() or {}

    endpoint = DiscoveredEndpoint(
        target_id=target_id,
        endpoint_path=data.get('path') or data.get('endpoint_path') or '/',
        method=data.get('method', 'GET'),
        description=data.get('description'),
        parameters=json.dumps(data.get('parameters', {})),
        response_schema=json.dumps(data.get('response_schema', {})),
        is_vulnerable=bool(data.get('is_vulnerable', False)),
        vulnerability_notes=data.get('vulnerability_notes'),
    )

    db.session.add(endpoint)
    log_action(user_id, 'create', 'endpoint', details=f'Added endpoint to target: {target.name}')
    db.session.commit()

    return jsonify({
        'message': 'Endpoint added successfully',
        'endpoint': {'id': endpoint.id, 'path': endpoint.endpoint_path},
    }), 201


@api_bp.route('/targets/endpoints/<endpoint_id>', methods=['DELETE'])
@jwt_required()
@require_role('admin', 'manager')
def delete_endpoint(endpoint_id):
    """Delete a discovered endpoint"""
    user_id = get_jwt_identity()
    endpoint = DiscoveredEndpoint.query.get_or_404(endpoint_id)
    
    db.session.delete(endpoint)
    log_action(user_id, 'delete', 'endpoint', endpoint_id, 'Deleted endpoint')
    db.session.commit()
    
    return jsonify({'message': 'Endpoint deleted successfully'})


@api_bp.route('/targets/<target_id>/test-connection', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def test_target_connection(target_id):
    """Low-level TCP reachability test for a target."""
    target = Target.query.get_or_404(target_id)
    from app.services.scan_service import ScannerService
    scanner = ScannerService()
    try:
        result = scanner.test_host_connection(target.host, target.port)
        return jsonify({
            'success': result.get('reachable', False),
            'latency': result.get('latency'),
            'message': ('Connection successful'
                        if result.get('reachable') else 'Connection failed')
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@api_bp.route('/targets/<target_id>/test-mcp', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def test_target_mcp(target_id):
    """Run a real MCP handshake + discovery against a target.

    Returns server info, transport used, list of tools/resources/prompts,
    and any auth-related errors. Used by the frontend "Test Connection"
    button in the Target modal.
    """
    target = Target.query.get_or_404(target_id)
    from app.services import mcp_client, attack_runner

    target_dict = attack_runner.prepare_target_dict({
        'host': target.host, 'port': target.port,
        'protocol': target.protocol, 'base_url': target.base_url,
        'target_type': target.target_type,
    }, target_row=target)

    client = mcp_client.MCPClient.from_target(target_dict, timeout=10)
    try:
        disc = client.discover()
    finally:
        client.close()

    # Shape the response for the UI
    if disc.get('initialized'):
        msg = (f"Connected. Server: "
               f"{(disc.get('server_info') or {}).get('name','?')}  "
               f"Proto: {disc.get('protocol_version','?')}")
    else:
        errs = disc.get('errors') or []
        first = errs[0] if errs else {}
        msg = (f"Handshake failed at step {first.get('step','init')}: "
               f"{first.get('error') or first.get('status') or 'no response'}")

    return jsonify({
        'success': bool(disc.get('initialized')),
        'message': msg,
        'transport': disc.get('transport'),
        'server_info': disc.get('server_info'),
        'protocol_version': disc.get('protocol_version'),
        'capabilities': disc.get('capabilities'),
        'tools_count': len(disc.get('tools') or []),
        'resources_count': len(disc.get('resources') or []),
        'prompts_count': len(disc.get('prompts') or []),
        'tools': [{'name': t.get('name'),
                   'description': (t.get('description') or '')[:200]}
                  for t in (disc.get('tools') or [])[:30]],
        'resources': [{'uri': r.get('uri'),
                       'name': r.get('name')}
                      for r in (disc.get('resources') or [])[:30]],
        'errors': disc.get('errors') or [],
    }), 200


@api_bp.route('/targets/types', methods=['GET'])
@jwt_required()
def get_target_types():
    """Get available target types"""
    return jsonify({
        'types': [
            {'value': 'mcp_server', 'label': 'MCP Server'},
            {'value': 'mcp_client', 'label': 'MCP Client'},
            {'value': 'acp_server', 'label': 'ACP Server'},
            {'value': 'llm_api', 'label': 'LLM API Endpoint'},
            {'value': 'rag_system', 'label': 'RAG System'},
            {'value': 'vector_db', 'label': 'Vector Database'},
            {'value': 'agent_orchestrator', 'label': 'Agent Orchestrator'},
            {'value': 'tool_server', 'label': 'Tool Server'},
            {'value': 'rest_api', 'label': 'REST API'},
            {'value': 'graphql_api', 'label': 'GraphQL API'},
            {'value': 'websocket', 'label': 'WebSocket Server'},
            {'value': 'grpc', 'label': 'gRPC Server'},
            {'value': 'custom', 'label': 'Custom Target'}
        ]
    })


@api_bp.route('/targets/environments', methods=['GET'])
@jwt_required()
def get_environments():
    """Get available environments"""
    return jsonify({
        'environments': [
            {'value': 'production', 'label': 'Production'},
            {'value': 'staging', 'label': 'Staging'},
            {'value': 'development', 'label': 'Development'},
            {'value': 'testing', 'label': 'Testing'},
            {'value': 'internal', 'label': 'Internal'},
            {'value': 'external', 'label': 'External'}
        ]
    })


@api_bp.route('/targets/import', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def import_targets():
    """Import multiple targets from JSON"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    targets_data = data.get('targets', [])
    if not targets_data:
        return jsonify({'error': 'No targets provided'}), 400
    
    created = 0
    errors = []
    
    for idx, t_data in enumerate(targets_data):
        try:
            if not t_data.get('name') or not t_data.get('host'):
                errors.append(f"Target {idx}: Missing name or host")
                continue
            
            target = Target(
                name=t_data['name'],
                target_type=t_data.get('target_type', 'custom'),
                host=t_data['host'],
                port=t_data.get('port'),
                protocol=t_data.get('protocol', 'https'),
                environment=t_data.get('environment', 'production'),
                status='active',
                description=t_data.get('description'),
                tags=json.dumps(t_data.get('tags', [])),
                created_by=user_id
            )
            db.session.add(target)
            created += 1
        except Exception as e:
            errors.append(f"Target {idx}: {str(e)}")
    
    log_action(user_id, 'import', 'target', details=f'Imported {created} targets')
    db.session.commit()
    
    return jsonify({
        'message': f'Imported {created} targets',
        'created': created,
        'errors': errors
    })
