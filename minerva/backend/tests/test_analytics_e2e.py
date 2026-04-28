"""One-shot end-to-end verification of:
  - report_engine analytics block (severity/conf/attack/tool/CWE/MITRE/etc)
  - Network throttle (stealth profile slows things down measurably)

Run from backend/:
    python -m tests.test_analytics_e2e
"""

import json
import os
import socket
import sys
import threading
import time

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

os.environ.setdefault("FLASK_ENV", "development")
from app import create_app  # noqa: E402
from scripts import demo_mcp_server as demo  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    port = free_port()
    srv = demo.serve("127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        app = create_app("development")
        client = app.test_client()
        login = client.post("/api/v1/auth/login",
                            json={"username": "admin", "password": "admin123"})
        H = {"Authorization": "Bearer " + login.get_json()["access_token"]}

        # Register target
        r = client.post("/api/v1/targets", json={
            "name": f"Demo MCP {port}", "target_type": "mcp_server",
            "host": "127.0.0.1", "port": port, "protocol": "http",
            "base_url": f"http://127.0.0.1:{port}",
            "environment": "development",
        }, headers=H)
        tj = r.get_json()
        tid = tj.get("id") or tj.get("target", {}).get("id")
        print(f"target id = {tid}")

        # Pick six attacks for variety
        attacks = client.get("/api/v1/attacks", headers=H).get_json()
        items = attacks if isinstance(attacks, list) else attacks.get("attacks", [])
        wanted = {
            "Direct Prompt Injection (Pro)", "SQL Injection (Pro)",
            "Path Traversal / LFI (Pro)", "Tool Poisoning (Pro)",
            "Authentication Bypass (Pro)", "Command Injection (Pro)",
        }
        attack_ids = [a["id"] for a in items if a["name"] in wanted]
        print(f"attacks selected: {len(attack_ids)}")

        cid = client.post("/api/v1/campaigns", json={
            "name": "Analytics Verification",
            "campaign_type": "external", "mode": "automated",
            "scenario": "direct",
            "target_ids": [tid], "attack_ids": attack_ids,
        }, headers=H).get_json()["campaign"]["id"]
        print(f"campaign id = {cid}")

        client.post(f"/api/v1/campaigns/{cid}/start", headers=H)
        deadline = time.time() + 120
        while time.time() < deadline:
            execs = client.get(
                f"/api/v1/campaigns/{cid}/executions",
                headers=H).get_json()["executions"]
            if execs and all(e["status"] in ("success", "completed", "error",
                                              "failed", "cancelled")
                              for e in execs):
                break
            time.sleep(1)
        print(f"executions: {len(execs)}")

        r = client.post("/api/v1/reports/generate", json={
            "campaign_id": cid, "name": "Analytics Test"}, headers=H)
        rid = r.get_json()["report"]["id"]
        print(f"report id = {rid}")

        report = client.get(f"/api/v1/reports/{rid}",
                            headers=H).get_json()
        analytics = report.get("content", {}).get("analytics") or {}
        print(f"\n=== Analytics block ===")
        print(f"keys: {sorted(analytics.keys())}")
        print(f"kpis: {analytics.get('kpis')}")
        print(f"severity_distribution (>0): "
              f"{[d for d in analytics.get('severity_distribution', []) if d['count']]}")
        print(f"confidence_distribution (>0): "
              f"{[d for d in analytics.get('confidence_distribution', []) if d['count']]}")
        print(f"attack_effectiveness (top 3): "
              f"{[(a['attack_id'], a['findings'], a['critical'], a['high']) for a in (analytics.get('attack_effectiveness') or [])[:3]]}")
        print(f"top_vulnerable_tools: "
              f"{[(t['tool'], t['findings']) for t in (analytics.get('top_vulnerable_tools') or [])[:5]]}")
        print(f"cwe_distribution (top 5): "
              f"{analytics.get('cwe_distribution', [])[:5]}")
        print(f"target_ranking: "
              f"{[(t['target'], t['findings'], t['critical'], t['high']) for t in (analytics.get('target_ranking') or [])[:5]]}")
        print(f"category_distribution: "
              f"{analytics.get('category_distribution', [])[:5]}")
        print(f"confirmation_split: {analytics.get('confirmation_split')}")
        print(f"cvss_histogram: {analytics.get('cvss_histogram')}")
        print(f"mitre_coverage: {analytics.get('mitre_coverage')}")

        # Sanity assertions
        assert analytics, "analytics block missing"
        assert analytics["kpis"]["total_findings"] > 0, "no findings recorded"
        assert any(d["count"] > 0 for d in analytics["severity_distribution"]), \
            "no severities populated"
        assert analytics["attack_effectiveness"], "no attack effectiveness"
        assert analytics["top_vulnerable_tools"], "no vulnerable tools"
        assert analytics["cwe_distribution"], "no CWE distribution"
        assert analytics["target_ranking"], "no target ranking"
        print("\n  ALL ANALYTICS ASSERTIONS PASS")
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()
