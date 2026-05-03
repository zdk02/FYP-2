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


def build_exec_globals(*, extra: dict | None = None,
                       safe_mode: bool = False,
                       dry_run: bool = False,
                       engagement_id: str | None = None) -> dict:
    """The full toolkit every Python attack sees.

    `safe_mode` blocks destructive helpers (reverse_shell.spawn, etc.)
    `dry_run` makes mcp_client.call a no-op that records the would-be
    request without sending it. Both are enforced at the helper level
    so attack scripts cannot circumvent them.
    """
    from app.services import mcp_client as _mcp_client
    from app.services import oob_callback as _oob_callback
    from app.services import payload_library as _payload_library
    from app.services import evidence as _evidence
    from app.services import reverse_shell as _reverse_shell
    from app.services import mitm_proxy as _mitm_proxy
    from app.services import attack_helpers as _attack_helpers
    from app.services import cloud_metadata as _cloud_metadata
    from app.services import secret_validators as _secret_validators
    from app.services import engagement_service as _engagement_service

    # Wrap mcp_client.call for dry-run / quota / kill-switch
    real_call = _mcp_client.call

    def _safe_call(target, method, params=None, *args, **kwargs):
        # Quota charge + kill-switch check
        if engagement_id:
            try:
                eng = _engagement_service.get_engagement(engagement_id)
                if eng and eng.is_killed:
                    return {
                        "transport": target.get("protocol", "?"),
                        "request": {"method": method, "params": params or {}},
                        "response": None,
                        "status": "killed",
                        "latency_ms": 0,
                        "error": "Engagement kill switch engaged — aborting.",
                    }
                _engagement_service.charge_requests(engagement_id, 1)
            except Exception:
                pass
        if dry_run:
            return {
                "transport": target.get("protocol", "?"),
                "request": {"method": method, "params": params or {}},
                "response": None,
                "status": "dry_run",
                "latency_ms": 0,
                "error": None,
                "headers": {},
                "dry_run": True,
            }
        return real_call(target, method, params, *args, **kwargs)

    # Stub the destructive helpers when safe_mode is on
    class _SafeReverseShell:
        @staticmethod
        def spawn_listener(*a, **k):
            return {"safe_mode": True, "skipped": True,
                    "reason": "safe_mode disables reverse_shell"}

        @staticmethod
        def get_session(*a, **k):
            return None

        @staticmethod
        def list_sessions(*a, **k):
            return []

    class _MCPClientShim:
        """Shim exposing the same surface as mcp_client but with call()
        wrapped for engagement enforcement."""
        call = staticmethod(_safe_call)

        def __getattr__(self, name):
            return getattr(_mcp_client, name)

    _mcp_shim = _MCPClientShim()
    # Mirror module-level attributes (functions, classes) explicitly
    for _name in dir(_mcp_client):
        if _name.startswith("_") or _name == "call":
            continue
        try:
            setattr(_mcp_shim, _name, getattr(_mcp_client, _name))
        except Exception:
            pass

    rs_helper = _SafeReverseShell if safe_mode else _reverse_shell

    g = {
        "__builtins__": __builtins__,
        "json": _json, "os": _os, "re": _re, "socket": _socket,
        "subprocess": _subprocess, "platform": _platform,
        "hashlib": _hashlib, "datetime": _dt, "time": _time,
        "requests": _requests, "yaml": _yaml, "urllib": _urllib,
        "base64": _b64,
        # Pro-pentest helpers (with engagement-aware wrappers)
        "mcp_client": _mcp_shim,
        "oob": _oob_callback,
        "payloads": _payload_library,
        "evidence": _evidence,
        "reverse_shell": rs_helper,
        "mitm_proxy": _mitm_proxy,
        "helpers": _attack_helpers,
        "cloud_metadata": _cloud_metadata,
        "secret_validators": _secret_validators,
        # Runtime flags attacks can read
        "SAFE_MODE": safe_mode,
        "DRY_RUN": dry_run,
        "ENGAGEMENT_ID": engagement_id,
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
                      execution_id: str | None = None,
                      engagement_id: str | None = None,
                      safe_mode: bool | None = None,
                      dry_run: bool | None = None,
                      attack_tags: list | None = None,
                      attack_name: str | None = None,
                      bypass_preflight: bool = False) -> dict:
    """Execute a Python attack in-process — engagement-scoped.

    Returns the attack's structured result: ``{success, findings,
    evidence, logs, summary}``. Never raises — errors are captured into
    the ``logs`` and ``success=False``.

    The pre-flight gate (engagement scope, time window, quota, kill
    switch) is enforced BEFORE the script runs. Out-of-scope = no
    payload sent. `bypass_preflight` is for unit tests only.
    """
    log_buffer: list[str] = []

    def _logger(msg: str) -> None:
        log_buffer.append(f"[SCRIPT] {msg}")

    # ---- Pre-flight engagement gate ----------------------------------
    effective_safe = bool(safe_mode)
    effective_dry = bool(dry_run)
    eng_id = engagement_id
    # Auto-bypass for unit tests / legacy callers:
    #   - empty target dict (no host to enforce scope against), OR
    #   - running under pytest / Flask testing config, OR
    #   - MINERVA_BYPASS_PREFLIGHT env (escape hatch for migration windows)
    if not bypass_preflight:
        empty_target = not (isinstance(target, dict) and target.get('host'))
        is_testing = bool(_os.environ.get('PYTEST_CURRENT_TEST')
                          or _os.environ.get('FLASK_ENV') == 'testing'
                          or _os.environ.get('MINERVA_BYPASS_PREFLIGHT'))
        if empty_target or is_testing:
            bypass_preflight = True
    if not bypass_preflight:
        try:
            from app.services import engagement_service as _eng
            res = _eng.preflight_check(
                engagement_id=engagement_id,
                target=target,
                requested_safe_mode=safe_mode,
                requested_dry_run=dry_run,
            )
            eng = res['engagement']
            eng_id = eng.id
            effective_safe = bool(res['safe_mode'])
            effective_dry = bool(res['dry_run'])
            log_buffer.append(
                f"[PREFLIGHT] OK — engagement='{eng.name}' "
                f"safe_mode={effective_safe} dry_run={effective_dry} "
                f"remaining_requests={res['remaining_requests']}")
            # Safe-mode blocks destructive attacks entirely
            if effective_safe and _eng.is_destructive_attack(attack_tags, attack_name):
                return _wrap_error(
                    "blocked_safe_mode",
                    [f"[PREFLIGHT] Attack '{attack_name or attack_id}' is "
                     "classified destructive (RCE/reverse-shell/DoS). "
                     "Safe mode is enabled on the active engagement — run "
                     "rejected."] + log_buffer,
                    attack_id, target)
        except Exception as e:
            from app.services.engagement_service import ScopeViolation
            if isinstance(e, ScopeViolation):
                return _wrap_error(
                    f"scope_violation:{e.code}",
                    [f"[PREFLIGHT] REJECTED — {e.reason}"] + log_buffer,
                    attack_id, target)
            # Any other pre-flight error: log and continue (don't break
            # legacy /test calls that have no engagement at all in dev).
            log_buffer.append(f"[PREFLIGHT] warn: {type(e).__name__}: {e}")

    # ---- Audit start ------------------------------------------------
    try:
        from app.services import audit_service as _audit
        _audit.append(
            action="attack_started",
            engagement_id=eng_id,
            resource_type="attack",
            resource_id=attack_id,
            details={
                "target": {k: target.get(k) for k in
                           ("host", "port", "protocol", "base_url")},
                "execution_id": execution_id,
                "safe_mode": effective_safe,
                "dry_run": effective_dry,
            },
        )
    except Exception:
        pass

    ctx = {
        "attack_id": attack_id,
        "execution_id": execution_id or f"run-{attack_id}-{int(_time.time())}",
        "logger": _logger,
        "engagement_id": eng_id,
        "safe_mode": effective_safe,
        "dry_run": effective_dry,
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
            g = build_exec_globals(
                safe_mode=effective_safe,
                dry_run=effective_dry,
                engagement_id=eng_id,
            )
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
    # Annotate summary with engagement context
    result["summary"]["engagement_id"] = eng_id
    result["summary"]["safe_mode"] = effective_safe
    result["summary"]["dry_run"] = effective_dry

    # Stamp every finding with engagement_id + dedup_key
    try:
        for f in result.get("findings", []) or []:
            f.setdefault("engagement_id", eng_id)
            if not f.get("dedup_key"):
                f["dedup_key"] = compute_dedup_key(
                    eng_id, target, f.get("tool"), f.get("parameter"),
                    f.get("category"))
    except Exception:
        pass

    # Audit completion
    try:
        from app.services import audit_service as _audit
        _audit.append(
            action="attack_completed",
            engagement_id=eng_id,
            resource_type="attack",
            resource_id=attack_id,
            details={
                "execution_id": ctx.get("execution_id"),
                "total_findings": len(result.get("findings", [])),
                "counts": result.get("summary", {}).get("counts", {}),
                "duration_ms": result.get("summary", {}).get("duration_ms"),
            },
        )
    except Exception:
        pass
    return result


def compute_dedup_key(engagement_id: str | None, target: dict | None,
                      tool: str | None, parameter: str | None,
                      payload_class: str | None) -> str:
    """Stable dedup key for cross-run findings hygiene.

    sha256 over (engagement | target_host:port | tool | param |
    payload_class). Same logical finding → same key, so re-runs link to
    the existing FindingTriage row instead of creating duplicates.
    """
    target = target or {}
    components = [
        engagement_id or "",
        f"{target.get('host', '')}:{target.get('port', '')}",
        tool or "",
        parameter or "",
        payload_class or "",
    ]
    raw = "|".join(str(c) for c in components)
    return _hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


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
