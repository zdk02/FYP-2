"""
Unit tests for Minerva core services.

Run:
    cd backend
    python -m tests.test_core_services

Exit 0 on all-green. Prints a pass/fail line per assertion group.
"""

from __future__ import annotations

import os
import sys
import threading
import time


BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


class R:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.log = []

    def check(self, cond, label):
        tag = "PASS" if cond else "FAIL"
        self.log.append(f"  [{tag}] {label}")
        if cond:
            self.passed += 1
        else:
            self.failed += 1
        return cond

    def dump(self):
        for line in self.log:
            print(line)
        print(f"\n{self.passed}/{self.passed + self.failed} passed")


# ---------------------------------------------------------------------------
# mcp_client
# ---------------------------------------------------------------------------

def test_mcp_client(r):
    print("\n=== mcp_client ===")
    from app.services import mcp_client as mc

    # Auth header composition
    h = mc.apply_auth({}, {"type": "bearer", "token": "abc"})
    r.check(h.get("Authorization") == "Bearer abc", "bearer auth header")

    h = mc.apply_auth({}, {"type": "api_key", "header": "X-K", "value": "v"})
    r.check(h.get("X-K") == "v", "api_key header")

    h = mc.apply_auth({}, {"type": "basic",
                            "username": "u", "password": "p"})
    r.check((h.get("Authorization") or "").startswith("Basic "), "basic auth")

    h = mc.apply_auth({}, {"type": "custom", "headers": {"X-A": "1"}})
    r.check(h.get("X-A") == "1", "custom headers")

    # Transport selection
    client = mc.MCPClient.from_target({"host": "x", "port": 80,
                                        "protocol": "http"}, timeout=1)
    r.check(client.transport.name == "http", "http transport default")
    client = mc.MCPClient.from_target({"host": "x", "port": 80,
                                        "protocol": "ws"}, timeout=1)
    r.check(client.transport.name == "ws", "ws transport via protocol")
    client = mc.MCPClient.from_target({"base_url": "http://x",
                                        "path": "/sse"}, timeout=1)
    r.check(client.transport.name == "sse", "sse transport via path")


# ---------------------------------------------------------------------------
# oob_callback (requires app context for the DB)
# ---------------------------------------------------------------------------

def test_oob_callback(r):
    print("\n=== oob_callback ===")
    from app.services import oob_callback as oob

    t = oob.mint("unit-test", ttl=60, metadata={"k": "v"})
    r.check(len(t.token) == 32, "token is 32 hex chars")
    r.check("/callbacks/oob/" in t.url, "url contains callback path")

    ok = oob.record_hit(t.token, source_ip="9.9.9.9",
                        method="GET", path="/x",
                        headers={"X-Y": "z"}, body="body")
    r.check(ok, "record_hit returns True for valid token")
    r.check(oob.record_hit("bad" * 16) is False,
            "record_hit returns False for unknown token")

    hits = oob.hits(t.token)
    r.check(len(hits) == 1 and hits[0]["source_ip"] == "9.9.9.9",
            "hits round-trip via DB")

    # Wait should return immediately since hit already exists
    t0 = time.time()
    got = oob.wait(t.token, timeout=2)
    r.check(len(got) == 1 and time.time() - t0 < 1.0,
            "wait returns hits without blocking")

    # Threaded: mint → later hit → wait wakes up. Push the Flask app
    # context into the worker thread so DB writes succeed.
    from flask import current_app
    app_obj = current_app._get_current_object()
    t2 = oob.mint("unit-test-wake", ttl=30)
    def _late():
        time.sleep(0.3)
        with app_obj.app_context():
            oob.record_hit(t2.token, source_ip="1.1.1.1")
    threading.Thread(target=_late, daemon=True).start()
    t0 = time.time()
    got = oob.wait(t2.token, timeout=3)
    r.check(len(got) == 1 and 0.2 < time.time() - t0 < 2.5,
            "wait blocks then wakes on hit")

    oob.release(t.token)
    oob.release(t2.token)


# ---------------------------------------------------------------------------
# payload_library
# ---------------------------------------------------------------------------

def test_payload_library(r):
    print("\n=== payload_library ===")
    from app.services import payload_library as pl
    # Assumes seed_pro_attacks has run
    cmd = pl.get("command_injection")
    r.check(len(cmd) >= 5, "command_injection has payloads")

    oob_cmd = pl.get("command_injection:oob")
    r.check(len(oob_cmd) >= 1
            and all("oob" in (p.get("tags") or [])
                    and "command_injection" in (p.get("tags") or [])
                    for p in oob_cmd),
            "AND-query returns rows matching every tag")

    r.check(pl.get("definitely_nonexistent_tag_xyz") == [],
            "unknown tag returns empty list")


# ---------------------------------------------------------------------------
# evidence / ReportBuilder
# ---------------------------------------------------------------------------

def test_evidence(r):
    print("\n=== evidence ===")
    from app.services import evidence as ev

    f = ev.Finding(attack_id="x", title="t", category="c",
                   severity="high", confidence="confirmed")
    d = f.to_dict()
    r.check(d["severity"] == "high" and d["confidence"] == "confirmed",
            "Finding preserves fields")
    r.check("id" in d and "timestamp" in d, "Finding has id + timestamp")
    r.check(d["evidence"] == [], "Finding has empty evidence list")

    f2 = ev.Finding(attack_id="x", title="t", category="c",
                    severity="not_a_thing", confidence="nope")
    r.check(f2.to_dict()["severity"] == "medium"
            and f2.to_dict()["confidence"] == "medium",
            "invalid severity/confidence fall back to medium")

    rb = ev.ReportBuilder("x", {"host": "h"})
    rb.info("hello")
    rb.add_finding(f)
    rb.add_finding(ev.Finding(attack_id="x", title="critical!",
                               category="c", severity="critical",
                               confidence="confirmed"))
    out = rb.finalize()
    r.check(out["success"] is True, "default finalize success=True")
    r.check(len(out["findings"]) == 2, "findings collected")
    counts = out["summary"]["counts"]
    r.check(counts["critical"] == 1 and counts["high"] == 1,
            "severity tally correct")
    r.check(counts["confirmed"] == 2, "confirmed tally correct")


# ---------------------------------------------------------------------------
# attack_runner (smoke)
# ---------------------------------------------------------------------------

def test_attack_runner(r):
    print("\n=== attack_runner ===")
    from app.services import attack_runner as ar

    # happy path
    script = (
        "def execute(target, params, context):\n"
        "    rb = evidence.ReportBuilder(context['attack_id'], target)\n"
        "    rb.info('ran')\n"
        "    rb.add_finding(evidence.Finding(attack_id='t', title='ok',\n"
        "        category='x', severity='low', confidence='low'))\n"
        "    return rb.finalize()\n"
    )
    res = ar.run_python_attack(script, target={"host": "x"}, params={},
                                attack_id="t")
    r.check(res["success"] is True and len(res["findings"]) == 1,
            "run_python_attack happy path")

    # missing execute
    bad = "x = 1\n"
    res = ar.run_python_attack(bad, target={}, params={}, attack_id="t")
    r.check(res["success"] is False, "script without execute() fails")

    # exception inside attack captured
    boom = ("def execute(target, params, context):\n"
            "    raise RuntimeError('boom')\n")
    res = ar.run_python_attack(boom, target={}, params={}, attack_id="t",
                                timeout=5)
    r.check(res["success"] is False
            and any("boom" in line for line in res["logs"]),
            "exception captured in logs without raising")

    # timeout
    hang = ("def execute(target, params, context):\n"
            "    import time; time.sleep(5)\n")
    res = ar.run_python_attack(hang, target={}, params={}, attack_id="t",
                                timeout=1)
    r.check(res["success"] is False
            and res.get("summary", {}).get("status") == "timeout",
            "timeout enforced")


# ---------------------------------------------------------------------------
# yaml_store (uses temp dir)
# ---------------------------------------------------------------------------

def test_yaml_store(r):
    print("\n=== yaml_store ===")
    import tempfile
    from app.services import yaml_store as ys

    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "data.yaml")
        ys.write_yaml(p, {"a": [1, 2, 3], "b": "hello"})
        data = ys.read_yaml(p)
        r.check(data == {"a": [1, 2, 3], "b": "hello"},
                "write + read round-trip")

        # Second write creates a backup
        ys.write_yaml(p, {"a": [1, 2], "b": "world"}, backup_keep=5)
        backups = ys.list_backups(p)
        r.check(len(backups) >= 1, "backup created on second write")

        # Validator rejects bad data
        def must_have_b(d):
            if "b" not in d:
                raise ValueError("b required")
        try:
            ys.write_yaml(p, {"a": [1]}, validator=must_have_b)
            r.check(False, "validator should have rejected")
        except ValueError:
            data_after = ys.read_yaml(p)
            r.check(data_after.get("b") == "world",
                    "file unchanged when validator rejects")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    from app import create_app
    app = create_app(os.environ.get("FLASK_ENV", "development"))
    app.app_context().push()

    r = R()
    test_mcp_client(r)
    test_oob_callback(r)
    test_payload_library(r)
    test_evidence(r)
    test_attack_runner(r)
    test_yaml_store(r)

    print("\n" + "=" * 60)
    print("UNIT TEST RESULTS")
    print("=" * 60)
    r.dump()
    return 0 if r.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
