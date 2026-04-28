"""
Validation + check-type registry for scanner plugin CVE data.

This is the single source of truth that both the write-path validators
and the `GET /check-types` endpoint read from. Adding a 14th check type
means adding one entry to CHECK_TYPE_SCHEMAS, updating the scanner
engine, and the frontend picks it up automatically.
"""

import re


SUPPORTED_SCHEMA_VERSIONS = {'3.0'}

SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}

CLIENT_TYPES = {
    'cli', 'ide', 'ide_extension', 'desktop_app', 'browser_extension',
    'web', 'mcp_server', 'proxy', 'debug_tool', 'other',
}

_CVE_ID_RE = re.compile(r'^[A-Z0-9]+(?:-[A-Z0-9]+){1,4}$')
_SLUG_RE = re.compile(r'^[a-z0-9_\-]+$')


# Per-type schema for env_checks / active_checks.
# Each entry describes required fields, optional fields, and a human label
# used by the frontend dynamic form builder.
CHECK_TYPE_SCHEMAS = {
    'file_exists': {
        'label': 'File exists',
        'required': ['path'],
        'optional': ['description'],
        'fields': {
            'path': {'type': 'string', 'placeholder': '~/.claude/settings.json'},
        },
    },
    'dir_exists': {
        'label': 'Directory exists',
        'required': ['path'],
        'optional': ['description'],
        'fields': {
            'path': {'type': 'string', 'placeholder': '~/.cursor/'},
        },
    },
    'file_contains': {
        'label': 'File contains regex',
        'required': ['path', 'pattern'],
        'optional': ['description'],
        'fields': {
            'path': {'type': 'string'},
            'pattern': {'type': 'string', 'placeholder': 'autoApprove'},
        },
    },
    'file_not_contains': {
        'label': 'File does NOT contain regex',
        'required': ['path', 'pattern'],
        'optional': ['description'],
        'fields': {
            'path': {'type': 'string'},
            'pattern': {'type': 'string'},
        },
    },
    'port_open': {
        'label': 'TCP port open',
        'required': ['port'],
        'optional': ['host', 'description'],
        'fields': {
            'host': {'type': 'string', 'default': '127.0.0.1'},
            'port': {'type': 'integer', 'min': 1, 'max': 65535},
        },
    },
    'ws_no_auth': {
        'label': 'WebSocket accepts no-auth handshake',
        'required': ['port'],
        'optional': ['host', 'description'],
        'fields': {
            'host': {'type': 'string', 'default': '127.0.0.1'},
            'port': {'type': 'integer', 'min': 1, 'max': 65535},
        },
    },
    'http_probe': {
        'label': 'HTTP probe',
        'required': ['url'],
        'optional': ['expect_status', 'description'],
        'fields': {
            'url': {'type': 'string', 'placeholder': 'http://127.0.0.1:8080/mcp'},
            'expect_status': {'type': 'array', 'items': 'integer', 'default': [200]},
        },
    },
    'http_header': {
        'label': 'HTTP response header present',
        'required': ['url', 'header'],
        'optional': ['description'],
        'fields': {
            'url': {'type': 'string'},
            'header': {'type': 'string', 'placeholder': 'x-mcp-version'},
        },
    },
    'command_output': {
        'label': 'Shell command output matches',
        'required': ['cmd'],
        'optional': ['expect_pattern', 'description'],
        'fields': {
            'cmd': {'type': 'string', 'placeholder': 'which sed'},
            'expect_pattern': {'type': 'string'},
        },
    },
    'config_json_value': {
        'label': 'JSON config key matches',
        'required': ['path', 'key', 'expect'],
        'optional': ['description'],
        'fields': {
            'path': {'type': 'string'},
            'key': {'type': 'string', 'placeholder': 'env.ANTHROPIC_BASE_URL'},
            'expect': {'type': 'string', 'placeholder': '.*'},
        },
    },
    'npm_installed': {
        'label': 'Global npm package below version',
        'required': ['package', 'vulnerable_below'],
        'optional': ['description'],
        'fields': {
            'package': {'type': 'string', 'placeholder': '@anthropic-ai/claude-code'},
            'vulnerable_below': {'type': 'string', 'placeholder': '2.0.31'},
        },
    },
    'process_running': {
        'label': 'Process running by name',
        'required': ['name'],
        'optional': ['description'],
        'fields': {
            'name': {'type': 'string', 'placeholder': 'claude'},
        },
    },
    'tcp_banner': {
        'label': 'TCP banner matches',
        'required': ['port'],
        'optional': ['host', 'expect', 'description'],
        'fields': {
            'host': {'type': 'string', 'default': '127.0.0.1'},
            'port': {'type': 'integer', 'min': 1, 'max': 65535},
            'expect': {'type': 'string'},
        },
    },
}


class ValidationError(ValueError):
    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field


def _require(obj, field, ctx):
    if field not in obj or obj.get(field) in (None, ''):
        raise ValidationError(f'{ctx}: missing required field "{field}"', field=field)


def validate_check(check):
    if not isinstance(check, dict):
        raise ValidationError('check must be an object')
    ctype = check.get('type')
    if not ctype:
        raise ValidationError('check.type is required', field='type')
    schema = CHECK_TYPE_SCHEMAS.get(ctype)
    if schema is None:
        raise ValidationError(f'unknown check type: {ctype}', field='type')
    for f in schema['required']:
        _require(check, f, f'check[{ctype}]')


def validate_cve(cve):
    if not isinstance(cve, dict):
        raise ValidationError('cve must be an object')
    for f in ('id', 'title', 'severity', 'description'):
        _require(cve, f, 'cve')
    cve_id = str(cve['id']).strip()
    if not _CVE_ID_RE.match(cve_id):
        raise ValidationError(
            f'cve.id must match [A-Z0-9]+(-[A-Z0-9]+)+ (got "{cve_id}")',
            field='id',
        )
    sev = str(cve['severity']).lower()
    if sev not in SEVERITIES:
        raise ValidationError(
            f'cve.severity must be one of {sorted(SEVERITIES)}',
            field='severity',
        )
    if 'cvss' in cve and cve['cvss'] not in (None, ''):
        try:
            score = float(cve['cvss'])
            if not (0.0 <= score <= 10.0):
                raise ValueError()
        except (TypeError, ValueError):
            raise ValidationError('cve.cvss must be a number 0-10', field='cvss')
    if 'references' in cve and cve['references'] is not None:
        if not isinstance(cve['references'], list):
            raise ValidationError('cve.references must be a list', field='references')
    for key in ('env_checks', 'active_checks'):
        items = cve.get(key) or []
        if not isinstance(items, list):
            raise ValidationError(f'cve.{key} must be a list', field=key)
        for i, chk in enumerate(items):
            try:
                validate_check(chk)
            except ValidationError as e:
                raise ValidationError(f'cve.{key}[{i}]: {e}', field=f'{key}[{i}]')


def validate_client(client):
    if not isinstance(client, dict):
        raise ValidationError('client must be an object')
    for f in ('display_name', 'vendor', 'type'):
        _require(client, f, 'client')
    ctype = str(client['type']).lower()
    if ctype not in CLIENT_TYPES:
        raise ValidationError(
            f'client.type must be one of {sorted(CLIENT_TYPES)}',
            field='type',
        )
    detection = client.get('detection') or {}
    if not isinstance(detection, dict):
        raise ValidationError('client.detection must be an object', field='detection')
    cves = client.get('cves') or []
    if not isinstance(cves, list):
        raise ValidationError('client.cves must be a list', field='cves')
    seen_ids = set()
    for i, cve in enumerate(cves):
        try:
            validate_cve(cve)
        except ValidationError as e:
            raise ValidationError(f'client.cves[{i}]: {e}', field=f'cves[{i}]')
        cid = cve['id']
        if cid in seen_ids:
            raise ValidationError(
                f'client.cves[{i}]: duplicate CVE id "{cid}"',
                field=f'cves[{i}].id',
            )
        seen_ids.add(cid)


def validate_globals(g):
    if not isinstance(g, dict):
        raise ValidationError('globals must be an object')
    for key in ('dangerous_config_patterns', 'remote_probe_paths',
                'websocket_probe_ports', 'interesting_headers'):
        if key in g and g[key] is not None and not isinstance(g[key], list):
            raise ValidationError(f'globals.{key} must be a list', field=key)
    ports = g.get('websocket_probe_ports') or []
    for i, p in enumerate(ports):
        try:
            pi = int(p)
            if not (1 <= pi <= 65535):
                raise ValueError()
        except (TypeError, ValueError):
            raise ValidationError(
                f'globals.websocket_probe_ports[{i}] must be 1-65535',
                field=f'websocket_probe_ports[{i}]',
            )
    for i, entry in enumerate(g.get('dangerous_config_patterns') or []):
        if not isinstance(entry, dict):
            raise ValidationError(
                f'globals.dangerous_config_patterns[{i}] must be an object',
                field=f'dangerous_config_patterns[{i}]',
            )
        if not entry.get('pattern'):
            raise ValidationError(
                f'globals.dangerous_config_patterns[{i}].pattern is required',
                field=f'dangerous_config_patterns[{i}].pattern',
            )


def validate_db(db):
    """Validate an entire cve_database.yaml document."""
    if not isinstance(db, dict):
        raise ValidationError('database must be an object')
    sv = str(db.get('schema_version', '')).strip()
    if sv and sv not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValidationError(
            f'schema_version {sv!r} is not supported (expected one of '
            f'{sorted(SUPPORTED_SCHEMA_VERSIONS)})',
            field='schema_version',
        )
    clients = db.get('clients') or {}
    if not isinstance(clients, dict):
        raise ValidationError('database.clients must be an object', field='clients')
    for key, client in clients.items():
        if not _SLUG_RE.match(str(key)):
            raise ValidationError(
                f'client key "{key}" must match [a-z0-9_-]+',
                field=f'clients.{key}',
            )
        try:
            validate_client(client)
        except ValidationError as e:
            raise ValidationError(f'clients.{key}: {e}', field=f'clients.{key}')
    validate_globals(db)


def check_types_list():
    """Serialisable form of CHECK_TYPE_SCHEMAS for the API."""
    return [
        {'type': t, **schema} for t, schema in CHECK_TYPE_SCHEMAS.items()
    ]
