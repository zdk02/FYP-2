"""
Execute a scanner plugin script in a controlled namespace.

Mirrors the attack execution pattern in api/attacks.py:test_attack but
adds the modules scanner plugins need (yaml, subprocess, platform, ...)
and sets __file__ so scripts that resolve sibling data files via
os.path.dirname(os.path.abspath(__file__)) keep working without any
patch.
"""

import concurrent.futures
import datetime as _datetime
import hashlib
import json as _json
import os
import platform as _platform
import re as _re
import socket as _socket
import subprocess as _subprocess
import time as _time
import traceback
import urllib

import requests as _requests
import yaml as _yaml

from flask import current_app

from app.services.scanner_registry import resolve_paths


class ScannerExecutionError(Exception):
    pass


def _build_exec_globals(script_path):
    return {
        '__builtins__': __builtins__,
        '__file__': os.path.abspath(script_path),
        '__name__': '__scanner_plugin__',
        'json': _json,
        'os': os,
        're': _re,
        'socket': _socket,
        'subprocess': _subprocess,
        'platform': _platform,
        'hashlib': hashlib,
        'datetime': _datetime,
        'time': _time,
        'requests': _requests,
        'yaml': _yaml,
        'urllib': urllib,
    }


_ENTRYPOINT_CANDIDATES = ('execute', 'run', 'scan')


def _pick_entrypoint(exec_locals):
    for name in _ENTRYPOINT_CANDIDATES:
        fn = exec_locals.get(name)
        if callable(fn):
            return name, fn
    return None, None


def _run_inner(script_path, target, params, context):
    with open(script_path, 'r', encoding='utf-8') as f:
        source = f.read()
    code = compile(source, script_path, 'exec')
    # Use a single namespace for both globals and locals so module-level
    # constants (e.g. _CURRENT_OS = platform.system().lower()) are visible
    # inside functions defined at module scope. Passing separate dicts causes
    # those assignments to land in locals while the functions close over
    # globals — a subtle NameError trap.
    ns = _build_exec_globals(script_path)
    exec(code, ns)

    name, fn = _pick_entrypoint(ns)
    if fn is None:
        raise ScannerExecutionError(
            'Scanner script must define execute(target, params, context), '
            'run(target, params, context), or scan(target, params, context)'
        )
    result = fn(target, params, context)
    if not isinstance(result, dict):
        raise ScannerExecutionError(
            f'Entrypoint {name}() must return a dict with keys '
            '{success, findings, evidence, logs}'
        )
    return result


def run_scanner(plugin_id, target, params, *, dry_run=False, execution_id=None, timeout=None):
    paths = resolve_paths(plugin_id)
    script_path = paths['script_path']
    cve_db_path = paths['cve_db_path']
    plugin_dir = paths['plugin_dir']

    if not os.path.isfile(script_path):
        raise ScannerExecutionError(f'Scanner script missing: {script_path}')

    started = _datetime.datetime.now(_datetime.timezone.utc)
    response = {
        'plugin_id': plugin_id,
        'target': target,
        'parameters_used': params,
        'dry_run': dry_run,
        'status': 'pending',
        'execution_log': [],
        'findings': [],
        'evidence': [],
        'started_at': started.isoformat(),
        'completed_at': None,
        'duration_ms': 0,
    }

    if dry_run:
        response['status'] = 'validated'
        response['execution_log'] = [
            f'[INFO] Scanner: {plugin_id}',
            f'[INFO] Script: {script_path}',
            f'[INFO] CVE DB: {cve_db_path}',
            f'[INFO] Target: {target}',
            f'[INFO] Params: {params}',
            '[INFO] Dry run — script not executed',
        ]
        response['completed_at'] = _datetime.datetime.now(_datetime.timezone.utc).isoformat()
        return response

    log = response['execution_log']
    log.append(f'[INFO] Executing scanner plugin: {plugin_id}')
    log.append(f'[INFO] Target: {target}')

    context = {
        'plugin_id': plugin_id,
        'plugin_dir': plugin_dir,
        'cve_db_path': cve_db_path,
        'execution_id': execution_id or f'scanner-{plugin_id}-{int(_time.time())}',
        'logger': lambda msg: log.append(f'[SCRIPT] {msg}'),
    }

    # Ensure params.cve_db_path is set so engines that honour it pick it up.
    params = dict(params or {})
    params.setdefault('cve_db_path', cve_db_path)

    max_seconds = timeout or current_app.config.get('SCANNER_MAX_EXEC_SECONDS', 180)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run_inner, script_path, target, params, context)
            try:
                result = future.result(timeout=max_seconds)
            except concurrent.futures.TimeoutError:
                response['status'] = 'timeout'
                log.append(f'[ERROR] Scanner exceeded {max_seconds}s timeout')
                return response

        # Normalize result
        response['findings'] = result.get('findings') or []
        response['evidence'] = result.get('evidence') or []
        for line in result.get('logs') or []:
            log.append(f'[SCRIPT] {line}')
        response['status'] = 'success' if result.get('success') else 'completed'
    except ScannerExecutionError as e:
        response['status'] = 'error'
        log.append(f'[ERROR] {e}')
    except Exception as e:
        response['status'] = 'error'
        log.append(f'[ERROR] {e}')
        log.append(f'[TRACEBACK] {traceback.format_exc()}')

    completed = _datetime.datetime.now(_datetime.timezone.utc)
    response['completed_at'] = completed.isoformat()
    response['duration_ms'] = int((completed - started).total_seconds() * 1000)
    return response
