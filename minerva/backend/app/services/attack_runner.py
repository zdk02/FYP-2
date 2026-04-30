"""
Shared attack execution engine.

Both the synchronous "Test" button (api/attacks.py:test_attack) and the
asynchronous campaign runner (services/attack_service.py) go through
this module so they share: same exec() sandbox, same helpers, same
target auth handling, same structured result shape.

Python attacks run in-process with the pro helpers injected. Other
languages (bash/ruby/javascript) still go through subprocess — those
are legacy and can't use the Python-first helpers anyway.
"""

from __future__ import annotations

import base64 as _b64
import concurrent.futures
import datetime as _dt
import hashlib as _hashlib
import json as _json
import os as _os
import platform as _platform
import re as _re
import socket as _socket
import subprocess as _subprocess
import tempfile
import time as _time
import traceback
import urllib as _urllib

import requests as _requests
import yaml as _yaml


_SUPPORTED_LANGS = {"python", "bash", "ruby", "javascript"}


def build_exec_globals(*, extra: dict | None = None) -> dict:
    """The full toolkit every Python attack sees."""
    from app.services import mcp_client as _mcp_client
    from app.services import oob_callback as _oob_callback
    from app.services import payload_library as _payload_library
    from app.services import evidence as _evidence
    from app.services import reverse_shell as _reverse_shell
    from app.services import mitm_proxy as _mitm_proxy
    from app.services import attack_helpers as _attack_helpers
    from app.services import cloud_metadata as _cloud_metadata
    from app.services import secret_validators as _secret_validators

    g = {
        "__builtins__": __builtins__,
        "json": _json, "os": _os, "re": _re, "socket": _socket,
        "subprocess": _subprocess, "platform": _platform,
        "hashlib": _hashlib, "datetime": _dt, "time": _time,
        "requests": _requests, "yaml": _yaml, "urllib": _urllib,
        "base64": _b64,
        # Pro-pentest helpers
        "mcp_client": _mcp_client,
        "oob": _oob_callback,
        "payloads": _payload_library,
        "evidence": _evidence,
        "reverse_shell": _reverse_shell,
        "mitm_proxy": _mitm_proxy,
        "helpers": _attack_helpers,
        "cloud_metadata": _cloud_metadata,
        "secret_validators": _secret_validators,
    }
    if extra:
        g.update(extra)
    return g


def prepare_target_dict(target_config: dict, target_row=None) -> dict:
    """Normalise + enrich a target dict for attack scripts.

    - Ensures base_url is set.
    - Pulls auth_config from the Target DB row when missing.
    - Respects explicit transport hints (stdio/ws/sse).
    """
    t = dict(target_config or {})
    host = t.get("host") or "localhost"
    port = t.get("port") or 80
    protocol = t.get("protocol") or "http"
    if not t.get("base_url"):
        t["base_url"] = f"{protocol}://{host}:{port}"
    if t.get("auth_config") is None and target_row is not None:
        raw = getattr(target_row, "auth_config", None)
        if raw:
            try:
                t["auth_config"] = _json.loads(raw)
            except Exception:
                pass
    return t


def run_python_attack(script_content: str, target: dict, params: dict,
                      *, attack_id: str, timeout: int = 300,
                      execution_id: str | None = None) -> dict:
    """Execute a Python attack in-process.

    Returns the attack's structured result: ``{success, findings,
    evidence, logs, summary}``. Never raises — errors are captured into
    the ``logs`` and ``success=False``.
    """
    log_buffer: list[str] = []

    def _logger(msg: str) -> None:
        log_buffer.append(f"[SCRIPT] {msg}")

    ctx = {
        "attack_id": attack_id,
        "execution_id": execution_id or f"run-{attack_id}-{int(_time.time())}",
        "logger": _logger,
    }

    # Capture the Flask app so the worker thread can push its own context
    # (ThreadPoolExecutor threads don't inherit app context — payload_library
    # queries would fail otherwise).
    try:
        from flask import current_app as _ca
        _app = _ca._get_current_object()
    except Exception:
        _app = None

    # Apply per-thread network shaping (stealth/balanced/aggressive +
    # delay/jitter/rps/concurrency overrides) before the script runs.
    # `runtime.from_params` builds the config; the inner thread re-applies
    # it because thread-locals don't cross thread boundaries.
    from app.services import runtime as _runtime
    _net_cfg = _runtime.from_params(params)
    # Strip the runtime knobs out of the dict the attack script sees.
    script_params = _runtime.strip_knobs(params)

    def _inner():
        _runtime.set_config(_net_cfg)
        try:
            g = build_exec_globals()
            exec(compile(script_content, "<attack>", "exec"), g)
            if "execute" not in g:
                raise RuntimeError(
                    "Attack script must define execute(target, params, context)")
            if _app is not None:
                with _app.app_context():
                    return g["execute"](target, script_params, ctx)
            return g["execute"](target, script_params, ctx)
        finally:
            _runtime.clear()

    started = _time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_inner)
            try:
                result = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                return _wrap_error("timeout",
                                   [f"[ERROR] Attack exceeded {timeout}s timeout"]
                                   + log_buffer, attack_id, target)
    except Exception as e:
        return _wrap_error(
            "error",
            [f"[ERROR] {type(e).__name__}: {e}",
             f"[TRACEBACK] {traceback.format_exc()}"] + log_buffer,
            attack_id, target,
        )

    if not isinstance(result, dict):
        return _wrap_error("error",
                           ["[ERROR] Attack returned non-dict; must return "
                            "{success, findings, evidence, logs}"]
                           + log_buffer,
                           attack_id, target)

    # Merge our logger buffer in front of script-provided logs
    script_logs = list(result.get("logs") or [])
    combined_logs = log_buffer + script_logs
    result["logs"] = combined_logs
    result.setdefault("findings", [])
    result.setdefault("evidence", [])
    if "summary" not in result:
        result["summary"] = {
            "attack_id": attack_id,
            "target": target,
            "started_at": _dt.datetime.fromtimestamp(
                started, tz=_dt.timezone.utc).isoformat(),
            "completed_at": _dt.datetime.now(
                _dt.timezone.utc).isoformat(),
            "duration_ms": int((_time.time() - started) * 1000),
            "total_findings": len(result["findings"]),
            "counts": _tally(result["findings"]),
        }
    return result


def run_subprocess_attack(script_content: str, language: str,
                          target: dict, params: dict, env: dict,
                          *, timeout: int = 300) -> dict:
    """Legacy path for non-Python attack scripts.

    Returns a normalised ``{success, findings, evidence, logs}`` dict.
    The script must print a JSON blob to stdout with those keys.
    """
    suffix = {"python": ".py", "bash": ".sh", "ruby": ".rb",
              "javascript": ".js"}.get(language, ".py")
    interp = {"python": ["python3"], "bash": ["bash"],
              "ruby": ["ruby"], "javascript": ["node"]}.get(language,
                                                             ["python3"])
    logs = [f"[INFO] subprocess runner: {language}"]
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(script_content)
        path = f.name
    try:
        proc = _subprocess.run(interp + [path], env=env,
                               capture_output=True, text=True, timeout=timeout)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        logs.append(f"[INFO] exit={proc.returncode}")
        if stderr:
            logs.append(f"[STDERR] {stderr[:2000]}")
        try:
            blob = _json.loads(stdout)
            return {
                "success": bool(blob.get("success", proc.returncode == 0)),
                "findings": blob.get("findings") or [],
                "evidence": blob.get("evidence") or [],
                "logs": logs + list(blob.get("logs") or []),
            }
        except _json.JSONDecodeError:
            logs.append("[WARN] script stdout was not JSON — returning raw")
            return {"success": proc.returncode == 0,
                    "findings": [], "evidence": [],
                    "logs": logs + [f"[STDOUT] {stdout[:4000]}"]}
    except _subprocess.TimeoutExpired:
        return _wrap_error("timeout",
                           logs + [f"[ERROR] subprocess timed out after {timeout}s"],
                           "subprocess", target)
    except Exception as e:
        return _wrap_error("error",
                           logs + [f"[ERROR] {e}"],
                           "subprocess", target)
    finally:
        try:
            _os.unlink(path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _wrap_error(status, logs, attack_id, target):
    return {
        "success": False,
        "findings": [],
        "evidence": [],
        "logs": list(logs),
        "summary": {
            "attack_id": attack_id,
            "target": target,
            "status": status,
            "completed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        },
    }


def _tally(findings):
    out = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    out["confirmed"] = 0
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        c = str(f.get("confidence", "")).lower()
        if s in out:
            out[s] += 1
        if c == "confirmed":
            out["confirmed"] += 1
    return out
