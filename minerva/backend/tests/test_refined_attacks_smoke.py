"""
Smoke tests for the 28 refined legacy attacks.

Runs every refined attack against the deliberately-vulnerable demo MCP
server. PASS = script runs without crashing and returns a well-formed
result dict. Does not assert specific finding categories (each refined
attack targets a distinct technique; demo only covers the subset
exploitable via our ten tools).
"""

from __future__ import annotations

import os
import sys
import time

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from tests.test_pro_attacks_e2e import _DemoServer   # noqa: E402


REFINED = [
    # Client
    "Direct Prompt Injection",
    "Indirect Prompt Injection",
    "Tool Poisoning",
    "Tool Shadowing",
    "Tool Name Conflict",
    "Tool Misuse via Malicious Metadata",
    "Tool Preference Manipulation",
    "Tool Coverage Hijacking",
    "Schema Inconsistencies",
    "Slash Command Overlap",
    "ConfusedAI Tool Misuse",
    "Multi-Tool Cooperation",
    "Infectious Attack",
    "MCP Credential Theft",
    "Vulnerable Client",
    # Transit
    "MCP Man In The Middle",
    "MCP Tool Rebinding",
    # Server
    "Command Injection",
    "Configuration Drift",
    "File-Based Injection (Addition)",
    "File-Based Injection (Deletion)",
    "File-Based Injection (Modification)",
    "File-Based Injection (Retrieval)",
    "MCP Server Backdoor Discovery",
    "Package Name Squatting",
    "Remote Code Execution",
    "SQL Injection",
    "Server Code Leakage",
]


def _run(name, target, *, params=None):
    from app.services import attack_runner
    from app.models import Attack
    a = Attack.query.filter_by(name=name).first()
    assert a is not None, f"{name!r} not in DB"
    return attack_runner.run_python_attack(
        a.script_content,
        target=attack_runner.prepare_target_dict(target),
        params=params or {"timeout": 3},
        attack_id=a.id,
        timeout=20,
    )


def main():
    from app import create_app
    app = create_app(os.environ.get("FLASK_ENV", "development"))
    app.app_context().push()

    passed = failed = 0
    with _DemoServer() as d:
        target = d.target()
        for name in REFINED:
            t0 = time.time()
            try:
                res = _run(name, target, params={"timeout": 3, "samples": 2,
                                                  "race_seconds": 1,
                                                  "capture_seconds": 2})
            except Exception as e:
                failed += 1
                print(f"  [FAIL] {name:48s} EXCEPTION: {e}")
                continue
            dt = int((time.time() - t0) * 1000)
            fc = len(res.get("findings") or [])
            lc = len(res.get("logs") or [])
            ok = isinstance(res, dict) and "findings" in res and "logs" in res
            if ok:
                passed += 1
                print(f"  [PASS] {name:48s} "
                      f"findings={fc}  logs={lc}  t={dt}ms")
            else:
                failed += 1
                print(f"  [FAIL] {name:48s} malformed result")

    print(f"\n{passed}/{passed + failed} refined attacks smoke-passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
