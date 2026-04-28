"""
Discover scanner plugins on disk and resolve their paths.

A plugin lives in backend/plugins/scanners/<plugin_id>/ and must contain
a plugin.yaml manifest whose top-level `id` matches the folder name. Any
data files referenced under `data_files:` are resolved relative to the
plugin folder.
"""

import os
import re
from datetime import datetime, timezone

from flask import current_app

from app.services.yaml_store import read_yaml


_SLUG_RE = re.compile(r'^[a-z0-9_\-]+$')


class PluginNotFound(Exception):
    pass


class PluginInvalid(Exception):
    pass


def _scanners_root():
    return current_app.config['SCANNERS_PLUGINS_FOLDER']


def _safe_plugin_id(plugin_id):
    pid = str(plugin_id or '').strip()
    if not _SLUG_RE.match(pid):
        raise PluginInvalid(f'Invalid plugin id: {plugin_id!r}')
    return pid


def plugin_dir(plugin_id):
    pid = _safe_plugin_id(plugin_id)
    root = _scanners_root()
    path = os.path.join(root, pid)
    if not os.path.isdir(path):
        raise PluginNotFound(f'Scanner plugin not found: {pid}')
    return path


def _manifest_path(pdir):
    return os.path.join(pdir, 'plugin.yaml')


def _script_path(pdir, manifest):
    name = manifest.get('script_file') or 'main.py'
    return os.path.join(pdir, name)


def _cve_db_path(pdir, manifest):
    data_files = manifest.get('data_files') or []
    for entry in data_files:
        if isinstance(entry, str) and entry.endswith('cve_database.yaml'):
            return os.path.join(pdir, entry)
        if isinstance(entry, dict) and entry.get('name', '').endswith('cve_database.yaml'):
            return os.path.join(pdir, entry['name'])
    default = os.path.join(pdir, 'cve_database.yaml')
    return default


def _readme_text(pdir):
    path = os.path.join(pdir, 'README.md')
    if not os.path.isfile(path):
        return ''
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except OSError:
        return ''


def _stats(db):
    clients = (db or {}).get('clients') or {}
    client_count = len(clients)
    cve_count = sum(len(c.get('cves') or []) for c in clients.values())
    return client_count, cve_count


def _summary(plugin_id, pdir, manifest, db_path, db):
    manifest = manifest or {}
    client_count, cve_count = _stats(db or {})
    try:
        updated_at = datetime.fromtimestamp(
            os.path.getmtime(db_path), tz=timezone.utc
        ).isoformat()
    except OSError:
        updated_at = None
    return {
        'id': plugin_id,
        'name': manifest.get('name') or plugin_id,
        'version': manifest.get('version'),
        'author': manifest.get('author'),
        'description': manifest.get('description'),
        'pillar': manifest.get('pillar'),
        'category': manifest.get('category'),
        'subcategory': manifest.get('subcategory'),
        'severity': manifest.get('severity'),
        'attack_type': manifest.get('attack_type'),
        'tags': manifest.get('tags') or [],
        'mitre_attack': manifest.get('mitre_attack'),
        'client_count': client_count,
        'cve_count': cve_count,
        'updated_at': updated_at,
    }


def list_plugins():
    root = _scanners_root()
    if not os.path.isdir(root):
        return []
    out = []
    for name in sorted(os.listdir(root)):
        pdir = os.path.join(root, name)
        if not os.path.isdir(pdir):
            continue
        if not _SLUG_RE.match(name):
            continue
        manifest_path = _manifest_path(pdir)
        if not os.path.isfile(manifest_path):
            continue
        try:
            manifest = read_yaml(manifest_path)
            db_path = _cve_db_path(pdir, manifest)
            db = read_yaml(db_path) if os.path.isfile(db_path) else {}
            out.append(_summary(name, pdir, manifest, db_path, db))
        except Exception:
            continue
    return out


def get_plugin(plugin_id, include_readme=True):
    pid = _safe_plugin_id(plugin_id)
    pdir = plugin_dir(pid)
    manifest = read_yaml(_manifest_path(pdir))
    declared_id = manifest.get('id')
    if declared_id and declared_id != pid:
        raise PluginInvalid(
            f'plugin.yaml id "{declared_id}" does not match folder "{pid}"'
        )
    db_path = _cve_db_path(pdir, manifest)
    db = read_yaml(db_path) if os.path.isfile(db_path) else {}
    summary = _summary(pid, pdir, manifest, db_path, db)
    summary['manifest'] = manifest
    summary['paths'] = {
        'plugin_dir': pdir,
        'script_path': _script_path(pdir, manifest),
        'cve_db_path': db_path,
    }
    summary['config_schema'] = manifest.get('config_schema') or {}
    summary['default_config'] = manifest.get('default_config') or {}
    summary['schema_version'] = db.get('schema_version') if isinstance(db, dict) else None
    if include_readme:
        summary['readme'] = _readme_text(pdir)
    return summary


def resolve_paths(plugin_id):
    pid = _safe_plugin_id(plugin_id)
    pdir = plugin_dir(pid)
    manifest = read_yaml(_manifest_path(pdir))
    return {
        'plugin_id': pid,
        'plugin_dir': pdir,
        'script_path': _script_path(pdir, manifest),
        'cve_db_path': _cve_db_path(pdir, manifest),
        'manifest': manifest,
    }
