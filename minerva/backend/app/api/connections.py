"""
Connection Scripts API routes
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app.api.users import admin_required
from app.models import ConnectionScript, AuditLog
from app import db
import json


@api_bp.route('/connections', methods=['GET'])
@jwt_required()
def get_connection_scripts():
    """Get all connection scripts"""
    server_type = request.args.get('server_type')
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    
    query = ConnectionScript.query
    
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    if server_type:
        query = query.filter_by(server_type=server_type)
    
    scripts = query.order_by(ConnectionScript.name).all()
    return jsonify([s.to_dict() for s in scripts]), 200


@api_bp.route('/connections/<script_id>', methods=['GET'])
@jwt_required()
def get_connection_script(script_id):
    """Get a specific connection script"""
    script = ConnectionScript.query.get(script_id)
    if not script:
        return jsonify({'error': 'Connection script not found'}), 404
    return jsonify(script.to_dict(include_script=True)), 200


@api_bp.route('/connections', methods=['POST'])
@admin_required
def create_connection_script():
    """Create a new connection script"""
    data = request.get_json()
    
    if not data.get('name') or not data.get('server_type') or not data.get('script_content'):
        return jsonify({'error': 'Name, server type, and script content required'}), 400
    
    script = ConnectionScript(
        name=data['name'],
        description=data.get('description', ''),
        server_type=data['server_type'],
        protocol=data.get('protocol'),
        script_content=data['script_content'],
        script_language=data.get('script_language', 'python'),
        config_schema=json.dumps(data.get('config_schema', {})),
        default_config=json.dumps(data.get('default_config', {})),
        is_active=data.get('is_active', True)
    )
    
    db.session.add(script)
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='create',
        resource_type='connection_script',
        resource_id=script.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(script.to_dict()), 201


@api_bp.route('/connections/<script_id>', methods=['PUT'])
@admin_required
def update_connection_script(script_id):
    """Update a connection script"""
    script = ConnectionScript.query.get(script_id)
    if not script:
        return jsonify({'error': 'Connection script not found'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        script.name = data['name']
    if 'description' in data:
        script.description = data['description']
    if 'server_type' in data:
        script.server_type = data['server_type']
    if 'protocol' in data:
        script.protocol = data['protocol']
    if 'script_content' in data:
        script.script_content = data['script_content']
    if 'script_language' in data:
        script.script_language = data['script_language']
    if 'config_schema' in data:
        script.config_schema = json.dumps(data['config_schema'])
    if 'default_config' in data:
        script.default_config = json.dumps(data['default_config'])
    if 'is_active' in data:
        script.is_active = data['is_active']
    
    # Audit log
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='update',
        resource_type='connection_script',
        resource_id=script.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(script.to_dict()), 200


@api_bp.route('/connections/<script_id>', methods=['DELETE'])
@admin_required
def delete_connection_script(script_id):
    """Delete a connection script"""
    script = ConnectionScript.query.get(script_id)
    if not script:
        return jsonify({'error': 'Connection script not found'}), 404
    
    # Audit log before deletion
    current_user_id = get_jwt_identity()
    log = AuditLog(
        user_id=current_user_id,
        action='delete',
        resource_type='connection_script',
        resource_id=script_id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(script)
    db.session.commit()
    
    return jsonify({'message': 'Connection script deleted'}), 200


@api_bp.route('/connections/server-types', methods=['GET'])
@jwt_required()
def get_server_types():
    """Get available server types"""
    types = [
        {'id': 'mcp_server', 'name': 'MCP Server', 'description': 'Model Context Protocol server'},
        {'id': 'acp_server', 'name': 'ACP Server', 'description': 'Agent Communication Protocol server'},
        {'id': 'llm_endpoint', 'name': 'LLM Endpoint', 'description': 'Large Language Model API endpoint'},
        {'id': 'rest_api', 'name': 'REST API', 'description': 'RESTful API endpoint'},
        {'id': 'graphql', 'name': 'GraphQL', 'description': 'GraphQL API endpoint'},
        {'id': 'websocket', 'name': 'WebSocket', 'description': 'WebSocket server'},
        {'id': 'grpc', 'name': 'gRPC', 'description': 'gRPC server'},
        {'id': 'rag_system', 'name': 'RAG System', 'description': 'Retrieval-Augmented Generation system'},
        {'id': 'vector_db', 'name': 'Vector Database', 'description': 'Vector database service'},
        {'id': 'agent_orchestrator', 'name': 'Agent Orchestrator', 'description': 'AI agent orchestration service'},
        {'id': 'custom', 'name': 'Custom', 'description': 'Custom server type'}
    ]
    return jsonify(types), 200


@api_bp.route('/connections/protocols', methods=['GET'])
@jwt_required()
def get_protocols():
    """Get available protocols"""
    protocols = [
        {'id': 'http', 'name': 'HTTP'},
        {'id': 'https', 'name': 'HTTPS'},
        {'id': 'ws', 'name': 'WebSocket'},
        {'id': 'wss', 'name': 'WebSocket Secure'},
        {'id': 'tcp', 'name': 'TCP'},
        {'id': 'udp', 'name': 'UDP'},
        {'id': 'grpc', 'name': 'gRPC'},
        {'id': 'stdio', 'name': 'Standard I/O'},
        {'id': 'sse', 'name': 'Server-Sent Events'}
    ]
    return jsonify(protocols), 200


@api_bp.route('/connections/<script_id>/test', methods=['POST'])
@jwt_required()
def test_connection_script(script_id):
    """Test a connection script by performing a real MCP probe against the
    host/port/auth resolved from the script's default_config merged with any
    body overrides.

    Body shape::

        {
          "config": {"host": "...", "port": 8080, "protocol": "http",
                      "path": "/mcp", "auth_config": {...}, "command": ...},
          "timeout": 10
        }
    """
    script = ConnectionScript.query.get(script_id)
    if not script:
        return jsonify({'error': 'Connection script not found'}), 404

    data = request.get_json() or {}
    override = data.get('config', {}) or {}
    timeout = int(data.get('timeout', 10) or 10)

    try:
        defaults = json.loads(script.default_config) if script.default_config else {}
    except Exception:
        defaults = {}
    merged = {**defaults, **override}

    # Build a Target-shaped dict the MCP client understands.
    target = {
        'host': merged.get('host', 'localhost'),
        'port': merged.get('port'),
        'protocol': merged.get('protocol') or script.protocol or 'http',
        'base_url': merged.get('base_url'),
        'path': merged.get('path'),
        'command': merged.get('command'),
        'transport': merged.get('transport') or script.protocol,
        'auth_config': merged.get('auth_config') or {},
        'verify_tls': merged.get('verify_tls'),
    }

    # Only MCP-shaped servers get a full handshake test. For anything else
    # we fall back to a TCP reachability probe so the user still gets a
    # useful answer.
    server_type = (script.server_type or '').lower()
    is_mcp_like = server_type in {'mcp_server', 'acp_server', 'agent_orchestrator'} or \
                  (target.get('path') or '').endswith(('/mcp', '/sse'))

    started = __import__('time').time()
    try:
        if is_mcp_like:
            from app.services.mcp_client import MCPClient
            with MCPClient.from_target(target, timeout=timeout) as mcp:
                init = mcp.initialize()
                if not init.get('ok'):
                    return jsonify({
                        'success': False,
                        'stage': 'initialize',
                        'error': init.get('error') or 'initialize failed',
                        'transport': init.get('transport'),
                        'status': init.get('status'),
                        'latency_ms': init.get('latency_ms'),
                    }), 200
                tools = mcp.tools_list()
                tool_count = len((tools.get('result') or {}).get('tools') or []) if tools.get('ok') else 0
                return jsonify({
                    'success': True,
                    'message': f'MCP handshake succeeded ({tool_count} tools)',
                    'transport': init.get('transport'),
                    'protocol_version': mcp.protocol_version,
                    'server_info': mcp.server_info,
                    'tool_count': tool_count,
                    'latency_ms': int((__import__('time').time() - started) * 1000),
                    'config_used': {k: v for k, v in merged.items() if k != 'auth_config'},
                }), 200

        # Non-MCP fallback: TCP reachability check.
        import socket as _socket
        host = target['host']
        port = int(target.get('port') or (443 if target['protocol'] == 'https' else 80))
        with _socket.create_connection((host, port), timeout=timeout):
            pass
        return jsonify({
            'success': True,
            'message': f'TCP reachable at {host}:{port}',
            'transport': 'tcp',
            'latency_ms': int((__import__('time').time() - started) * 1000),
            'config_used': {k: v for k, v in merged.items() if k != 'auth_config'},
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)[:500],
            'latency_ms': int((__import__('time').time() - started) * 1000),
            'config_used': {k: v for k, v in merged.items() if k != 'auth_config'},
        }), 200
