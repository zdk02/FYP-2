"""
Atomic YAML read/write with per-path locking and rolling backups.

Used by the scanner plugin subsystem to safely mutate cve_database.yaml
and any other editable YAML data file. Writes go through a tmp file +
os.replace so a crash mid-write cannot corrupt the file. A timestamped
copy of the previous file is placed in a sibling .backups/ directory.
"""

import os
import shutil
import tempfile
import threading
import uuid
from datetime import datetime, timezone

import yaml


_locks_guard = threading.Lock()
_locks = {}


def _lock_for(path):
    abs_path = os.path.abspath(path)
    with _locks_guard:
        lock = _locks.get(abs_path)
        if lock is None:
            lock = threading.Lock()
            _locks[abs_path] = lock
        return lock


def read_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def _backups_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(path)), '.backups')


def list_backups(path):
    d = _backups_dir(path)
    if not os.path.isdir(d):
        return []
    basename = os.path.basename(path)
    prefix = basename.rsplit('.', 1)[0] + '.'
    entries = []
    for name in os.listdir(d):
        if not name.startswith(prefix):
            continue
        full = os.path.join(d, name)
        try:
            stat = os.stat(full)
        except OSError:
            continue
        entries.append({
            'filename': name,
            'path': full,
            'size': stat.st_size,
            'created_at': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    entries.sort(key=lambda e: e['filename'], reverse=True)
    return entries


def _trim_backups(path, keep):
    d = _backups_dir(path)
    if not os.path.isdir(d):
        return
    basename = os.path.basename(path)
    prefix = basename.rsplit('.', 1)[0] + '.'
    items = [n for n in os.listdir(d) if n.startswith(prefix)]
    items.sort(reverse=True)
    for stale in items[keep:]:
        try:
            os.remove(os.path.join(d, stale))
        except OSError:
            pass


def _make_backup(path):
    if not os.path.isfile(path):
        return None
    d = _backups_dir(path)
    os.makedirs(d, exist_ok=True)
    basename = os.path.basename(path)
    stem, _, ext = basename.rpartition('.')
    if not stem:
        stem, ext = basename, 'yaml'
    ts = datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H-%M-%S-%fZ')
    backup = os.path.join(d, f'{stem}.{ts}.{ext}')
    shutil.copy2(path, backup)
    return backup


def write_yaml(path, data, validator=None, backup_keep=20):
    """Atomically write YAML `data` to `path`.

    validator: optional callable(data) -> None that raises ValueError on
        invalid shape. Called before any file mutation.
    backup_keep: retain this many rotated backups of the previous file.
    """
    if validator is not None:
        validator(data)

    abs_path = os.path.abspath(path)
    lock = _lock_for(abs_path)
    with lock:
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        backup = _make_backup(abs_path)

        tmp_name = f'.{os.path.basename(abs_path)}.tmp.{uuid.uuid4().hex}'
        tmp_path = os.path.join(os.path.dirname(abs_path), tmp_name)
        try:
            with open(tmp_path, 'w', encoding='utf-8', newline='\n') as f:
                yaml.safe_dump(
                    data,
                    f,
                    sort_keys=False,
                    allow_unicode=True,
                    width=4096,
                    default_flow_style=False,
                )
            os.replace(tmp_path, abs_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

        _trim_backups(abs_path, backup_keep)
        return {
            'path': abs_path,
            'size': os.path.getsize(abs_path),
            'backup': backup,
        }


def restore_backup(path, filename):
    """Restore a previously created backup file over `path`.

    `filename` is the basename inside .backups/, as returned by list_backups().
    """
    d = _backups_dir(path)
    safe_name = os.path.basename(filename)
    src = os.path.join(d, safe_name)
    if not os.path.isfile(src):
        raise FileNotFoundError(f'Backup not found: {safe_name}')

    with open(src, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}

    abs_path = os.path.abspath(path)
    lock = _lock_for(abs_path)
    with lock:
        _make_backup(abs_path)
        tmp_name = f'.{os.path.basename(abs_path)}.tmp.{uuid.uuid4().hex}'
        tmp_path = os.path.join(os.path.dirname(abs_path), tmp_name)
        try:
            with open(tmp_path, 'w', encoding='utf-8', newline='\n') as f:
                yaml.safe_dump(
                    data, f,
                    sort_keys=False, allow_unicode=True,
                    width=4096, default_flow_style=False,
                )
            os.replace(tmp_path, abs_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

    return {'restored_from': safe_name, 'path': abs_path}
