"""E2E for the report edit flow.

  - Generate a real report against the demo MCP server
  - PUT /reports/<id> with name, summary, recommendations, notes
  - GET /reports/<id> and assert all fields round-trip
  - Override one finding's severity → assert analytics recompute
  - Download HTML and check the new sections appear
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
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p


def main():
    port = free_port()
    srv = demo.serve("127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    try:
        app = create_app("development")
        client = app.test_client()
        H = {"Authorization": "Bearer " + client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"}
        ).get_json()["access_token"]}

        r = client.post("/api/v1/targets", json={
            "name": f"Demo MCP {port}", "target_type": "mcp_server",
            "host": "127.0.0.1", "port": port, "protocol": "http",
            "base_url": f"http://127.0.0.1:{port}",
            "environment": "development",
        }, headers=H)
        tid = r.get_json().get("id") or r.get_json().get("target", {}).get("id")

        attacks = client.get("/api/v1/attacks", headers=H).get_json()
        items = attacks if isinstance(attacks, list) else attacks.get("attacks", [])
        attack_ids = [a["id"] for a in items if a["name"] in {
            "Direct Prompt Injection (Pro)", "SQL Injection (Pro)",
            "Path Traversal / LFI (Pro)",
        }]

        cid = client.post("/api/v1/campaigns", json={
            "name": "Edit-Flow Test",
            "campaign_type": "external", "mode": "automated",
            "scenario": "direct",
            "target_ids": [tid], "attack_ids": attack_ids,
        }, headers=H).get_json()["campaign"]["id"]

        client.post(f"/api/v1/campaigns/{cid}/start", headers=H)
        deadline = time.time() + 90
        while time.time() < deadline:
            execs = client.get(f"/api/v1/campaigns/{cid}/executions",
                               headers=H).get_json()["executions"]
            if execs and all(e["status"] in ("success", "completed", "error",
                                              "failed", "cancelled")
                              for e in execs):
                break
            time.sleep(1)

        r = client.post("/api/v1/reports/generate", json={
            "campaign_id": cid, "name": "Edit-Flow Report"
        }, headers=H)
        rid = r.get_json()["report"]["id"]
        print(f"report id = {rid}")

        # ---- Round 1: edit narrative fields ----
        new_name = "Quarterly MCP Pentest — Acme Corp Q2"
        new_summary = (
            "This engagement focused on Acme's customer-facing MCP gateway "
            "in the staging cluster.\n\nThe assessment uncovered systemic "
            "issues in tool input validation and authentication enforcement. "
            "We strongly recommend remediation before any production exposure."
        )
        new_recs = [
            "Add output sanitization on all eval-style tools.",
            "Reject zero-width unicode in tool descriptions during catalogue indexing.",
            "Adopt a deny-by-default authn policy for every tool, not just admin_wipe.",
            "Add rate-limiting at the JSON-RPC layer (recommend 10 rps / IP).",
        ]
        new_notes = (
            "Engagement window: 2026-04-25 → 2026-04-26.\nStaging cluster only.\n"
            "OOB callbacks reached us from the demo egress — production may have "
            "tighter egress filtering, results may differ."
        )

        r = client.put(f"/api/v1/reports/{rid}", json={
            "name": new_name,
            "client_name": "Acme Corp",
            "assessor": "Minerva Lab",
            "executive_summary": new_summary,
            "recommendations": new_recs,
            "notes": new_notes,
        }, headers=H)
        print(f"PUT status: {r.status_code}")
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        c = body["content"]

        assert body["name"] == new_name
        assert c["meta"]["client_name"] == "Acme Corp"
        assert c["meta"]["assessor"] == "Minerva Lab"
        assert c["executive_summary"] == new_summary
        assert c["recommendations_override"] == new_recs
        assert c["notes"] == new_notes
        print("  narrative fields persisted")

        # ---- Round 2: override a finding severity ----
        if c["findings"]:
            fid = c["findings"][0]["id"]
            sev_before = c["findings"][0]["severity"]
            new_sev = "low" if sev_before != "low" else "info"
            r = client.put(f"/api/v1/reports/{rid}", json={
                "findings_overrides": {fid: {
                    "severity": new_sev,
                    "notes": "demoted after triage — false-equivalent",
                }}
            }, headers=H)
            assert r.status_code == 200, r.get_json()
            c2 = r.get_json()["content"]
            assert c2["findings"][0]["severity"] == new_sev
            assert c2["findings"][0]["analyst_notes"]
            # Analytics rebuilt to match
            sev_dist = {d["key"]: d["count"]
                        for d in c2["analytics"]["severity_distribution"]}
            assert sev_dist[new_sev] >= 1, (sev_before, new_sev, sev_dist)
            print(f"  finding severity override: {sev_before} -> {new_sev}, analytics recomputed")

        # ---- Round 3: HTML export carries the new sections ----
        r = client.get(f"/api/v1/reports/{rid}/download?format=html", headers=H)
        html = r.data.decode("utf-8")
        assert "<h2>Recommendations</h2>" in html, "Recommendations section missing in HTML"
        assert "<h2>Analyst Notes</h2>" in html, "Notes section missing in HTML"
        assert new_recs[0] in html, "First recommendation missing in HTML"
        assert "Acme Corp" in html, "client name missing"
        print("  HTML export contains Recommendations + Notes")

        # ---- Round 4: PDF export still renders ----
        r = client.get(f"/api/v1/reports/{rid}/download?format=pdf", headers=H)
        assert r.status_code == 200 and len(r.data) > 5000, "PDF export too small"
        print(f"  PDF export ok ({len(r.data)} bytes)")

        print("\n  ALL EDIT-FLOW ASSERTIONS PASS")
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()
