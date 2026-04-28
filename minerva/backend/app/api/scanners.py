"""
Scanner plugin REST API.

Scanners live on disk as YAML-backed plugins under
backend/plugins/scanners/<plugin_id>/. This blueprint exposes:

  - Discovery:   GET /scanners, GET /scanners/:id
  - Execution:   POST /scanners/:id/run
  - CVE CRUD:    CRUD on clients and CVEs inside cve_database.yaml
  - Globals:     dangerous_config_patterns, probe paths, ports, headers
  - Metadata:    GET /scanners/:id/check-types
  - Backups:     list + restore
"""

import copy
import json
import os
import re

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.api import api_bp
from app.api.users import admin_required
from app.models import AuditLog
from app import db

from app.services import cve_schema, yaml_store, scanner_registry, scanner_runner
from app.services.cve_schema import ValidationError as SchemaValidationError


_SAFE_KEY_RE = re.compile(r'^[a-zA-Z0-9_\-\.\:]+$')


def _safe_key(value, field):
    if value is None or not _SAFE_KEY_RE.match(str(value)):
        _raise_400(f'invalid {field}: {value!r}', field)
    return str(value)


def _raise_400(msg, field=None):
    resp = {'error': msg}
    if field:
        resp['field'] = field
    return jsonify(resp), 400


def _audit(action, resource_id, details=None):
    uid = get_jwt_identity()
    log = AuditLog(
        user_id=uid,
        action=action,
        resource_type='scanner',
        resource_id=resource_id,
        details=json.dumps(details) if details else None,
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()


def _load_db(plugin_id):
    paths = scanner_registry.resolve_paths(plugin_id)
    data = yaml_store.read_yaml(paths['cve_db_path'])
    return paths, data or {}


def _save_db(paths, data, validator=None):
    backup_keep = 20
    try:
        from flask import current_app
        backup_keep = current_app.config.get('SCANNER_BACKUP_KEEP', 20)
    except Exception:
        pass
    return yaml_store.write_yaml(
        paths['cve_db_path'],
        data,
        validator=validator,
        backup_keep=backup_keep,
    )


def _ensure_clients_key(data):
    if 'clients' not in data or data['clients'] is None:
        data['clients'] = {}
    elif not isinstance(data['clients'], dict):
        _raise_400('malformed cve_database: clients must be an object', 'clients')


def _cve_summary(client_key, client, cve):
    return {
        'client_key': client_key,
        'client_display_name': client.get('display_name'),
        'client_type': client.get('type'),
        'client_vendor': client.get('vendor'),
        'cve_id': cve.get('id'),
        'title': cve.get('title'),
        'severity': cve.get('severity'),
        'cvss': cve.get('cvss'),
        'cwe': cve.get('cwe'),
        'affected_versions': cve.get('affected_versions'),
        'fixed_version': cve.get('fixed_version'),
        'disclosure_date': cve.get('disclosure_date'),
        'env_checks_count': len(cve.get('env_checks') or []),
        'active_checks_count': len(cve.get('active_checks') or []),
    }


def _client_summary(key, client):
    cves = client.get('cves') or []
    return {
        'key': key,
        'display_name': client.get('display_name'),
        'vendor': client.get('vendor'),
        'type': client.get('type'),
        'detection': client.get('detection') or {},
        'cves_count': len(cves),
    }


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------

@api_bp.route('/scanners', methods=['GET'])
@jwt_required()
def list_scanners():
    return jsonify(scanner_registry.list_plugins()), 200


@api_bp.route('/scanners/<plugin_id>', methods=['GET'])
@jwt_required()
def get_scanner(plugin_id):
    try:
        data = scanner_registry.get_plugin(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    except scanner_registry.PluginInvalid as e:
        return jsonify({'error': str(e)}), 400
    return jsonify(data), 200


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

@api_bp.route('/scanners/<plugin_id>/run', methods=['POST'])
@jwt_required()
def run_scanner(plugin_id):
    try:
        scanner_registry.plugin_dir(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    except scanner_registry.PluginInvalid as e:
        return jsonify({'error': str(e)}), 400

    body = request.get_json() or {}
    target = body.get('target') or {
        'host': 'localhost',
        'port': 8080,
        'protocol': 'http',
    }
    target.setdefault('base_url',
        f"{target.get('protocol', 'http')}://{target.get('host', 'localhost')}:{target.get('port', 8080)}")
    params = body.get('params') or {}
    dry_run = bool(body.get('dry_run', False))

    result = scanner_runner.run_scanner(plugin_id, target, params, dry_run=dry_run)

    _audit(
        action='run' if not dry_run else 'dry_run',
        resource_id=plugin_id,
        details={'target': target, 'dry_run': dry_run, 'status': result.get('status')},
    )
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# CVE listing / CRUD
# ---------------------------------------------------------------------------

@api_bp.route('/scanners/<plugin_id>/cves', methods=['GET'])
@jwt_required()
def list_cves(plugin_id):
    try:
        _paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404

    clients = data.get('clients') or {}
    filter_client = request.args.get('client')
    filter_severity = request.args.get('severity')
    search = (request.args.get('search') or '').lower()

    out = []
    for key, client in clients.items():
        if filter_client and filter_client != key:
            continue
        for cve in client.get('cves') or []:
            if filter_severity and str(cve.get('severity', '')).lower() != filter_severity.lower():
                continue
            if search:
                blob = ' '.join(str(v) for v in (
                    cve.get('id'), cve.get('title'), cve.get('description'),
                    cve.get('cwe'), cve.get('reported_by'),
                ) if v).lower()
                if search not in blob and search not in key.lower():
                    continue
            out.append(_cve_summary(key, client, cve))
    return jsonify(out), 200


@api_bp.route('/scanners/<plugin_id>/clients', methods=['GET'])
@jwt_required()
def list_clients(plugin_id):
    try:
        _paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    clients = data.get('clients') or {}
    return jsonify([_client_summary(k, c) for k, c in clients.items()]), 200


@api_bp.route('/scanners/<plugin_id>/clients/<client_key>', methods=['GET'])
@jwt_required()
def get_client(plugin_id, client_key):
    _safe_key(client_key, 'client_key')
    try:
        _paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    clients = data.get('clients') or {}
    if client_key not in clients:
        return jsonify({'error': 'Client not found'}), 404
    return jsonify({'key': client_key, **clients[client_key]}), 200


@api_bp.route('/scanners/<plugin_id>/clients', methods=['POST'])
@admin_required
def create_client(plugin_id):
    body = request.get_json() or {}
    key = body.get('key')
    if not key:
        return _raise_400('key is required', 'key')
    _safe_key(key, 'key')
    try:
        paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    _ensure_clients_key(data)
    if key in data['clients']:
        return _raise_400(f'Client "{key}" already exists', 'key')

    client_obj = {
        'display_name': body.get('display_name') or '',
        'vendor': body.get('vendor') or '',
        'type': body.get('type') or 'other',
        'detection': body.get('detection') or {},
        'cves': body.get('cves') or [],
    }
    try:
        cve_schema.validate_client(client_obj)
    except SchemaValidationError as e:
        return _raise_400(str(e), getattr(e, 'field', None))

    data['clients'][key] = client_obj
    _save_db(paths, data, validator=cve_schema.validate_db)
    _audit('create_client', plugin_id, {'client_key': key})
    return jsonify({'key': key, **client_obj}), 201


@api_bp.route('/scanners/<plugin_id>/clients/<client_key>', methods=['PUT'])
@admin_required
def update_client(plugin_id, client_key):
    _safe_key(client_key, 'client_key')
    body = request.get_json() or {}
    try:
        paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    clients = data.get('clients') or {}
    if client_key not in clients:
        return jsonify({'error': 'Client not found'}), 404

    client = copy.deepcopy(clients[client_key])
    for field in ('display_name', 'vendor', 'type', 'detection'):
        if field in body:
            client[field] = body[field]
    try:
        cve_schema.validate_client(client)
    except SchemaValidationError as e:
        return _raise_400(str(e), getattr(e, 'field', None))

    data['clients'][client_key] = client
    _save_db(paths, data, validator=cve_schema.validate_db)
    _audit('update_client', plugin_id, {'client_key': client_key})
    return jsonify({'key': client_key, **client}), 200


@api_bp.route('/scanners/<plugin_id>/clients/<client_key>', methods=['DELETE'])
@admin_required
def delete_client(plugin_id, client_key):
    _safe_key(client_key, 'client_key')
    try:
        paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    clients = data.get('clients') or {}
    if client_key not in clients:
        return jsonify({'error': 'Client not found'}), 404
    del data['clients'][client_key]
    _save_db(paths, data, validator=cve_schema.validate_db)
    _audit('delete_client', plugin_id, {'client_key': client_key})
    return ('', 204)


@api_bp.route('/scanners/<plugin_id>/clients/<client_key>/cves/<cve_id>', methods=['GET'])
@jwt_required()
def get_cve(plugin_id, client_key, cve_id):
    _safe_key(client_key, 'client_key')
    _safe_key(cve_id, 'cve_id')
    try:
        _paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    client = (data.get('clients') or {}).get(client_key)
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    for cve in client.get('cves') or []:
        if cve.get('id') == cve_id:
            return jsonify(cve), 200
    return jsonify({'error': 'CVE not found'}), 404


@api_bp.route('/scanners/<plugin_id>/clients/<client_key>/cves', methods=['POST'])
@admin_required
def create_cve(plugin_id, client_key):
    _safe_key(client_key, 'client_key')
    body = request.get_json() or {}
    try:
        paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    client = (data.get('clients') or {}).get(client_key)
    if not client:
        return jsonify({'error': 'Client not found'}), 404

    cve_id = body.get('id')
    if not cve_id:
        return _raise_400('cve.id is required', 'id')
    existing = {c.get('id') for c in client.get('cves') or []}
    if cve_id in existing:
        return _raise_400(f'CVE "{cve_id}" already exists in client "{client_key}"', 'id')

    try:
        cve_schema.validate_cve(body)
    except SchemaValidationError as e:
        return _raise_400(str(e), getattr(e, 'field', None))

    client.setdefault('cves', []).append(body)
    data['clients'][client_key] = client
    _save_db(paths, data, validator=cve_schema.validate_db)
    _audit('create_cve', plugin_id, {'client_key': client_key, 'cve_id': cve_id})
    return jsonify(body), 201


@api_bp.route('/scanners/<plugin_id>/clients/<client_key>/cves/<cve_id>', methods=['PUT'])
@admin_required
def update_cve(plugin_id, client_key, cve_id):
    _safe_key(client_key, 'client_key')
    _safe_key(cve_id, 'cve_id')
    body = request.get_json() or {}
    if 'id' not in body:
        body['id'] = cve_id
    if body.get('id') != cve_id:
        return _raise_400('Changing a CVE id is not allowed via PUT', 'id')

    try:
        paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    client = (data.get('clients') or {}).get(client_key)
    if not client:
        return jsonify({'error': 'Client not found'}), 404

    cves = client.get('cves') or []
    idx = next((i for i, c in enumerate(cves) if c.get('id') == cve_id), None)
    if idx is None:
        return jsonify({'error': 'CVE not found'}), 404

    try:
        cve_schema.validate_cve(body)
    except SchemaValidationError as e:
        return _raise_400(str(e), getattr(e, 'field', None))

    cves[idx] = body
    client['cves'] = cves
    data['clients'][client_key] = client
    _save_db(paths, data, validator=cve_schema.validate_db)
    _audit('update_cve', plugin_id, {'client_key': client_key, 'cve_id': cve_id})
    return jsonify(body), 200


@api_bp.route('/scanners/<plugin_id>/clients/<client_key>/cves/<cve_id>', methods=['DELETE'])
@admin_required
def delete_cve(plugin_id, client_key, cve_id):
    _safe_key(client_key, 'client_key')
    _safe_key(cve_id, 'cve_id')
    try:
        paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    client = (data.get('clients') or {}).get(client_key)
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    cves = client.get('cves') or []
    new_cves = [c for c in cves if c.get('id') != cve_id]
    if len(new_cves) == len(cves):
        return jsonify({'error': 'CVE not found'}), 404
    client['cves'] = new_cves
    data['clients'][client_key] = client
    _save_db(paths, data, validator=cve_schema.validate_db)
    _audit('delete_cve', plugin_id, {'client_key': client_key, 'cve_id': cve_id})
    return ('', 204)


# ---------------------------------------------------------------------------
# Globals & metadata
# ---------------------------------------------------------------------------

_GLOBAL_KEYS = (
    'dangerous_config_patterns',
    'remote_probe_paths',
    'websocket_probe_ports',
    'interesting_headers',
)


@api_bp.route('/scanners/<plugin_id>/globals', methods=['GET'])
@jwt_required()
def get_globals(plugin_id):
    try:
        _paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    return jsonify({
        'schema_version': data.get('schema_version'),
        **{k: data.get(k) or [] for k in _GLOBAL_KEYS},
    }), 200


@api_bp.route('/scanners/<plugin_id>/globals', methods=['PUT'])
@admin_required
def update_globals(plugin_id):
    body = request.get_json() or {}
    try:
        paths, data = _load_db(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404

    merged = copy.deepcopy(data)
    for k in _GLOBAL_KEYS:
        if k in body:
            merged[k] = body[k]
    try:
        cve_schema.validate_globals(merged)
    except SchemaValidationError as e:
        return _raise_400(str(e), getattr(e, 'field', None))

    _save_db(paths, merged, validator=cve_schema.validate_db)
    _audit('update_globals', plugin_id, {'keys': list(body.keys())})
    return jsonify({
        'schema_version': merged.get('schema_version'),
        **{k: merged.get(k) or [] for k in _GLOBAL_KEYS},
    }), 200


@api_bp.route('/scanners/<plugin_id>/check-types', methods=['GET'])
@jwt_required()
def get_check_types(plugin_id):
    try:
        scanner_registry.plugin_dir(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    return jsonify(cve_schema.check_types_list()), 200


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

@api_bp.route('/scanners/<plugin_id>/backups', methods=['GET'])
@admin_required
def list_scanner_backups(plugin_id):
    try:
        paths = scanner_registry.resolve_paths(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    return jsonify(yaml_store.list_backups(paths['cve_db_path'])), 200


@api_bp.route('/scanners/<plugin_id>/restore', methods=['POST'])
@admin_required
def restore_scanner_backup(plugin_id):
    body = request.get_json() or {}
    filename = body.get('filename')
    if not filename:
        return _raise_400('filename is required', 'filename')
    if '/' in filename or '\\' in filename or '..' in filename:
        return _raise_400('invalid filename', 'filename')
    try:
        paths = scanner_registry.resolve_paths(plugin_id)
    except scanner_registry.PluginNotFound:
        return jsonify({'error': 'Scanner not found'}), 404
    try:
        result = yaml_store.restore_backup(paths['cve_db_path'], filename)
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404
    _audit('restore', plugin_id, {'filename': filename})
    return jsonify(result), 200
