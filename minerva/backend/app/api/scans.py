"""
Scan Management API Routes
Handles network scanning, service discovery, and attack surface mapping
"""

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api import api_bp
from app import db
from app.models.models import ScanJob, Target, DiscoveredEndpoint, User, AuditLog
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


@api_bp.route('/scans', methods=['GET'])
@jwt_required()
def get_scans():
    """Get all scan jobs with filtering"""
    scan_type = request.args.get('type')
    status = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = ScanJob.query
    
    if scan_type:
        query = query.filter(ScanJob.scan_type == scan_type)
    if status:
        query = query.filter(ScanJob.status == status)
    
    pagination = query.order_by(ScanJob.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    scans = []
    for s in pagination.items:
        results = json.loads(s.results) if s.results else {}
        scans.append({
            'id': s.id,
            'name': s.name,
            'scan_type': s.scan_type,
            'status': s.status,
            'progress': s.progress,
            'targets_discovered': results.get('hosts_found', 0),
            'started_at': s.started_at.isoformat() if s.started_at else None,
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'created_at': s.created_at.isoformat()
        })
    
    return jsonify({
        'scans': scans,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@api_bp.route('/scans/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    """Get detailed scan information"""
    scan = ScanJob.query.get_or_404(scan_id)

    target_spec = json.loads(scan.scan_config) if scan.scan_config else {}

    return jsonify({
        'id': scan.id,
        'name': scan.name,
        'scan_type': scan.scan_type,
        'status': scan.status,
        'progress': scan.progress,
        'target_range': scan.target_range,
        'target_specification': target_spec,
        'configuration': target_spec,
        'results': json.loads(scan.results) if scan.results else {},
        'error_message': scan.error_message,
        'created_by': scan.initiated_by,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'created_at': scan.created_at.isoformat()
    })


@api_bp.route('/scans', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def create_scan():
    """Create a new scan job"""
    user_id = get_jwt_identity()
    data = request.get_json()

    # Accept both legacy `target_specification` (object) and the simpler
    # frontend `target_range` (string).
    target_spec = data.get('target_specification')
    target_range = data.get('target_range')
    if not target_spec and not target_range:
        return jsonify({'error': 'Target specification or target_range is required'}), 400
    if not target_spec:
        target_spec = {'host': target_range, 'network': target_range}
    if not target_range:
        target_range = target_spec.get('host') or target_spec.get('network') or ''

    scan = ScanJob(
        name=data.get('name', f'Scan {datetime.utcnow().strftime("%Y-%m-%d %H:%M")}'),
        scan_type=data.get('scan_type', 'network'),
        target_range=target_range,
        scan_config=json.dumps({**target_spec, **data.get('configuration', {})}),
        initiated_by=user_id
    )
    
    db.session.add(scan)
    log_action(user_id, 'create', 'scan', details=f'Created scan: {scan.name}')
    db.session.commit()
    
    return jsonify({
        'message': 'Scan job created successfully',
        'scan': {
            'id': scan.id,
            'name': scan.name,
            'status': scan.status
        }
    }), 201


@api_bp.route('/scans/<scan_id>/start', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def start_scan(scan_id):
    """Start a scan job"""
    user_id = get_jwt_identity()
    scan = ScanJob.query.get_or_404(scan_id)

    if scan.status == 'running':
        return jsonify({'error': 'Scan is already running'}), 400
    if scan.status == 'completed':
        return jsonify({'error': 'Scan is already completed'}), 400

    # Update status
    scan.status = 'running'
    scan.started_at = datetime.utcnow()
    scan.progress = 0
    db.session.commit()

    # Start the scan
    from app.services.scan_service import ScannerService
    scanner = ScannerService()

    merged = json.loads(scan.scan_config) if scan.scan_config else {}
    if scan.target_range and 'host' not in merged and 'network' not in merged:
        merged.setdefault('host', scan.target_range)
        merged.setdefault('network', scan.target_range)
    target_spec = merged
    config = merged
    
    try:
        if scan.scan_type == 'network':
            results = scanner.scan_network(
                target_spec.get('network', target_spec.get('host')),
                config.get('ports', '1-1000'),
                timeout=config.get('timeout', 2)
            )
        elif scan.scan_type == 'port':
            results = scanner.scan_ports(
                target_spec.get('host'),
                config.get('ports', '1-65535'),
                timeout=config.get('timeout', 1)
            )
        elif scan.scan_type == 'service':
            results = scanner.enumerate_services(
                target_spec.get('host'),
                config.get('ports', [80, 443, 8080])
            )
        elif scan.scan_type == 'ai_endpoint':
            results = scanner.discover_ai_endpoints(
                target_spec.get('host'),
                target_spec.get('port', 443)
            )
        elif scan.scan_type == 'mcp':
            results = scanner.discover_mcp_servers(
                target_spec.get('network', target_spec.get('host'))
            )
        else:
            results = {'error': f'Unknown scan type: {scan.scan_type}'}
        
        scan.results = json.dumps(results)
        scan.status = 'completed'
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        
    except Exception as e:
        scan.status = 'error'
        scan.error_message = str(e)[:2000]
        scan.completed_at = datetime.utcnow()
    
    log_action(user_id, 'start', 'scan', scan_id, f'Started scan: {scan.name}')
    db.session.commit()
    
    return jsonify({
        'message': 'Scan completed',
        'scan': {
            'id': scan.id,
            'status': scan.status,
            'results': json.loads(scan.results) if scan.results else {}
        }
    })


@api_bp.route('/scans/<scan_id>/stop', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def stop_scan(scan_id):
    """Stop a running scan"""
    user_id = get_jwt_identity()
    scan = ScanJob.query.get_or_404(scan_id)

    if scan.status != 'running':
        return jsonify({'error': 'Scan is not running'}), 400

    scan.status = 'stopped'
    log_action(user_id, 'stop', 'scan', scan_id, f'Stopped scan: {scan.name}')
    db.session.commit()

    return jsonify({'message': 'Scan stopped'})


@api_bp.route('/scans/<scan_id>', methods=['DELETE'])
@jwt_required()
@require_role('admin', 'manager')
def delete_scan(scan_id):
    """Delete a scan job"""
    user_id = get_jwt_identity()
    scan = ScanJob.query.get_or_404(scan_id)

    if scan.status == 'running':
        return jsonify({'error': 'Cannot delete a running scan'}), 400

    scan_name = scan.name
    db.session.delete(scan)
    log_action(user_id, 'delete', 'scan', scan_id, f'Deleted scan: {scan_name}')
    db.session.commit()

    return jsonify({'message': 'Scan deleted successfully'})


@api_bp.route('/scans/<scan_id>/import-targets', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def import_scan_targets(scan_id):
    """Import discovered hosts as targets"""
    user_id = get_jwt_identity()
    scan = ScanJob.query.get_or_404(scan_id)
    data = request.get_json()
    
    if scan.status != 'completed':
        return jsonify({'error': 'Scan is not completed'}), 400
    
    results = json.loads(scan.results) if scan.results else {}
    hosts = results.get('hosts', [])
    
    if not hosts:
        return jsonify({'error': 'No hosts found in scan results'}), 400
    
    # Filter hosts if specific ones selected
    selected_hosts = data.get('hosts')
    if selected_hosts:
        hosts = [h for h in hosts if h.get('ip') in selected_hosts or h.get('hostname') in selected_hosts]
    
    created_count = 0
    errors = []
    environment = data.get('environment', 'external')
    tags = data.get('tags', ['scan-imported'])

    for host in hosts:
        try:
            ip = host.get('ip') or host.get('hostname')
            if not ip:
                errors.append('host missing ip/hostname')
                continue
            existing = Target.query.filter_by(host=ip).first()
            if existing:
                continue
            ports = host.get('ports') or []
            primary_port = ports[0] if ports else None
            target = Target(
                name=host.get('hostname') or ip,
                description=f'Imported from scan {scan.name}',
                target_type='generic',
                host=ip,
                port=primary_port,
                protocol='http',
                environment=environment,
                tags=json.dumps(tags),
                is_active=True,
            )
            db.session.add(target)
            created_count += 1
        except Exception as e:
            errors.append(f"{host.get('ip', 'unknown')}: {str(e)}")

    db.session.commit()
    log_action(user_id, 'import', 'scan', scan_id, f'Imported {created_count} targets from scan')

    return jsonify({
        'message': f'Imported {created_count} targets',
        'created': created_count,
        'errors': errors
    })


@api_bp.route('/scans/<scan_id>/hosts/import', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def import_single_host_as_target(scan_id):
    """Import a single discovered host from a scan as a Target.

    Body: { "host": "1.2.3.4", "name"?: "...", "port"?: 8080, "protocol"?: "http",
            "target_type"?: "mcp_server", "environment"?: "external" }
    """
    user_id = get_jwt_identity()
    ScanJob.query.get_or_404(scan_id)
    data = request.get_json() or {}

    host = data.get('host') or data.get('ip') or data.get('hostname')
    if not host:
        return jsonify({'error': 'host is required'}), 400

    existing = Target.query.filter_by(host=host).first()
    if existing:
        return jsonify({
            'message': 'Target already exists',
            'target': existing.to_dict() if hasattr(existing, 'to_dict') else {'id': existing.id, 'host': existing.host},
            'created': False,
        }), 200

    target = Target(
        name=data.get('name') or data.get('hostname') or host,
        description=data.get('description', f'Imported from scan {scan_id}'),
        target_type=data.get('target_type', 'generic'),
        host=host,
        port=data.get('port'),
        protocol=data.get('protocol', 'http'),
        environment=data.get('environment', 'external'),
        tags=json.dumps(data.get('tags', ['scan-imported'])),
        is_active=True,
    )
    db.session.add(target)
    log_action(user_id, 'create', 'target', target.id, f'Imported target {host} from scan {scan_id}')
    db.session.commit()

    return jsonify({
        'message': 'Target imported',
        'target': target.to_dict() if hasattr(target, 'to_dict') else {'id': target.id, 'host': host},
        'created': True,
    }), 201


@api_bp.route('/scans/quick-scan', methods=['POST'])
@jwt_required()
@require_role('admin', 'manager', 'operator')
def quick_scan():
    """Run a quick scan (create + start in one call)"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data.get('target'):
        return jsonify({'error': 'Target is required'}), 400
    
    scan_type = data.get('scan_type', 'network')
    target = data['target']
    
    # Create scan job
    scan = ScanJob(
        name=f'Quick Scan - {target}',
        scan_type=scan_type,
        target_range=target,
        scan_config=json.dumps({'host': target, 'network': target, **data.get('configuration', {})}),
        initiated_by=user_id
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Start the scan
    return start_scan(scan.id)


@api_bp.route('/scans/types', methods=['GET'])
@jwt_required()
def get_scan_types():
    """Get available scan types"""
    return jsonify({
        'types': [
            {
                'value': 'network',
                'label': 'Network Discovery',
                'description': 'Discover live hosts on a network'
            },
            {
                'value': 'port',
                'label': 'Port Scan',
                'description': 'Scan ports on specific hosts'
            },
            {
                'value': 'service',
                'label': 'Service Enumeration',
                'description': 'Enumerate services on discovered ports'
            },
            {
                'value': 'ai_endpoint',
                'label': 'AI Endpoint Discovery',
                'description': 'Discover AI-related API endpoints'
            },
            {
                'value': 'mcp',
                'label': 'MCP Server Discovery',
                'description': 'Find MCP servers on the network'
            },
            {
                'value': 'vulnerability',
                'label': 'Vulnerability Scan',
                'description': 'Basic vulnerability assessment'
            }
        ]
    })


@api_bp.route('/scans/presets', methods=['GET'])
@jwt_required()
def get_scan_presets():
    """Get predefined scan configurations"""
    return jsonify({
        'presets': [
            {
                'name': 'Quick Scan',
                'scan_type': 'network',
                'configuration': {
                    'ports': '22,80,443,8080,8443',
                    'timeout': 1
                }
            },
            {
                'name': 'Full Port Scan',
                'scan_type': 'port',
                'configuration': {
                    'ports': '1-65535',
                    'timeout': 0.5
                }
            },
            {
                'name': 'Common Ports',
                'scan_type': 'port',
                'configuration': {
                    'ports': '21,22,23,25,53,80,110,143,443,993,995,3306,3389,5432,8080,8443',
                    'timeout': 1
                }
            },
            {
                'name': 'AI Infrastructure',
                'scan_type': 'ai_endpoint',
                'configuration': {
                    'check_openai': True,
                    'check_anthropic': True,
                    'check_mcp': True,
                    'check_custom': True
                }
            },
            {
                'name': 'Web Ports Only',
                'scan_type': 'service',
                'configuration': {
                    'ports': [80, 443, 8080, 8443, 3000, 5000, 8000]
                }
            }
        ]
    })


@api_bp.route('/scans/validate-target', methods=['POST'])
@jwt_required()
def validate_target():
    """Validate and parse target specification"""
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    from app.services.scan_service import ScannerService
    scanner = ScannerService()
    
    try:
        # Parse the target
        import ipaddress
        
        result = {
            'valid': True,
            'type': None,
            'hosts': [],
            'message': ''
        }
        
        # Check if it's a CIDR
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                result['type'] = 'cidr'
                result['hosts'] = [str(ip) for ip in list(network.hosts())[:10]]  # First 10 for preview
                result['total_hosts'] = network.num_addresses - 2
                result['message'] = f'Network with {result["total_hosts"]} usable hosts'
            except ValueError:
                result['valid'] = False
                result['message'] = 'Invalid CIDR notation'
        
        # Check if it's a range
        elif '-' in target and not target.startswith('-'):
            parts = target.split('-')
            if len(parts) == 2:
                result['type'] = 'range'
                result['message'] = f'IP range from {parts[0]} to {parts[1]}'
        
        # Check if it's an IP
        elif target.replace('.', '').isdigit():
            try:
                ipaddress.ip_address(target)
                result['type'] = 'ip'
                result['hosts'] = [target]
                result['message'] = 'Single IP address'
            except ValueError:
                result['valid'] = False
                result['message'] = 'Invalid IP address'
        
        # Assume it's a hostname
        else:
            result['type'] = 'hostname'
            result['hosts'] = [target]
            result['message'] = 'Hostname (will be resolved)'
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'valid': False,
            'message': str(e)
        }), 400
