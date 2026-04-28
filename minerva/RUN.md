# Minerva — Complete Run Guide

One document with everything needed to run, test, and demo the
framework. Pick a section.

```
1.  30-second native run
2.  30-second Docker run
3.  Full FYP demo (5 minutes)
4.  Running the test suites
5.  Multi-MCP vulnerable lab
6.  Pentesting a real MCP server
7.  Generating pro reports (HTML / PDF / JSON / SARIF)
8.  Notifier — Slack / generic webhook
9.  Plugins & extensibility
10. Troubleshooting
```

---

## 1. 30-second native run

Two terminals, from `minerva/`:

```bash
# Terminal A — backend (Flask on :5000, SQLite by default)
cd backend
pip install -r requirements.txt           # first time only
python -m scripts.seed_pro_attacks        # first time only — seeds 44 attacks + 66 payloads
python run.py

# Terminal B — frontend (Vite dev on :5173)
cd frontend
npm install                                # first time only
npm run dev
```

Open **http://localhost:5173** → log in `admin@minerva.local / admin123`.

---

## 2. 30-second Docker run

From `minerva/`:

```bash
docker compose up -d --build
docker exec -it aegis-backend python -m scripts.seed_pro_attacks
```

Open **http://localhost** (port 80 — nginx serves the frontend).

`docker-compose.yml` is already wired for:
- Postgres + Redis
- `extra_hosts: host.docker.internal:host-gateway` so attacks can reach
  LAN services on your host.
- Volume mounts for plugins, instance DB, migration script.

---

## 3. Full FYP demo (5 minutes)

Four terminals:

```bash
# T1 — the multi-MCP vulnerable lab (4 servers, 17 tools total)
cd minerva/backend
python -m scripts.demo_lab
#   SQL-heavy MCP    :8701   (SQLi, error disclosure)
#   Filesystem MCP   :8702   (path traversal, arbitrary write)
#   Runtime MCP      :8703   (SSRF, RCE, pickle deser)
#   Protected MCP    :8704   (weak auth, prompt-poisoned tools)

# T2 — Minerva backend
python run.py

# T3 — Minerva frontend
cd minerva/frontend && npm run dev

# T4 — prove everything works
cd minerva/backend
python -m tests.test_pro_attacks_e2e        # 11/11 attacks confirmed
python -m tests.test_refined_attacks_smoke  # 28/28 refined attacks OK
python -m tests.test_core_services          # 32/32 unit tests
```

In the browser:

1. **Targets → + Add Target** four times — one per lab server
   (`127.0.0.1:8701..8704`, protocol `http`). For port 8704 set auth
   `Bearer Token` with any non-empty value (the lab accepts any token —
   Auth Bypass will catch that).
2. **Campaigns → + New Campaign** — pick all four targets + all 44 active
   attacks. Save, then **Start**.
3. After it completes: **Reports → + Generate from Campaign** → select
   the campaign → Generate. The report appears instantly with a risk
   grade (A-F), CVSS-scored findings, and executive summary.
4. Click the **HTML / PDF / JSON / SARIF** icons to download any format.

For a **real external target** demo, also create a Target pointing at
one of the servers in `backend/docs/REAL_MCP_TARGETS.md`.

---

## 4. Running the test suites

```bash
cd minerva/backend
# 11 end-to-end attack tests against the demo server
python -m tests.test_pro_attacks_e2e

# 28 refined-attack smoke tests (run without crashing)
python -m tests.test_refined_attacks_smoke

# 32 unit tests for mcp_client / oob / payloads / evidence / attack_runner / yaml_store
python -m tests.test_core_services
```

All three exit 0 when green. Expected:

```
11 / 11   integration
28 / 28   refined smoke
32 / 32   unit
===
71 / 71   assertions passing
```

---

## 5. Multi-MCP vulnerable lab

See above. The lab is 4 distinct vulnerable MCP servers — the intent
is to mirror an enterprise environment where different internal tools
expose different classes of bug.

Stop all four with Ctrl+C in T1.

---

## 6. Pentesting a real MCP server

Full step-by-step: **`backend/docs/REAL_MCP_TARGETS.md`**.

TL;DR for external + authenticated:

1. Set `MINERVA_OOB_URL` so OOB-confirmed attacks can receive callbacks:
   ```bash
   export MINERVA_OOB_URL="https://your-public-host.example.com"
   # or ngrok:
   ngrok http 5000   # copy the https URL into MINERVA_OOB_URL
   ```
2. Add a Target with the server's URL + auth token.
3. Click **Test Connection** — confirms MCP handshake, lists tools.
4. Attacks → pick one → Test → select that target → Run.

**Only test systems you own or have authorisation for.**

---

## 7. Generating pro reports

Reports are driven by Campaigns (aggregate of many attack executions).

### From the UI
1. **Reports → + Generate from Campaign** → pick campaign → Generate.
2. Download as **HTML** (branded, print-ready), **PDF** (paged),
   **JSON** (full structured data), or **SARIF 2.1.0** (industry
   standard; imports into GitHub Advanced Security, VS Code SARIF
   viewer, etc.).

### From the API
```bash
TOKEN=$(curl -s localhost:5000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@minerva.local","password":"admin123"}' \
  | jq -r .access_token)

# Build and persist a report
curl -X POST localhost:5000/api/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"campaign_id":"<CAMPAIGN-ID>", "client_name":"Acme Corp",
       "name":"Q3 MCP Pentest"}'

# Download formats
curl -H "Authorization: Bearer $TOKEN" \
  "localhost:5000/api/v1/reports/<REPORT-ID>/download?format=pdf" \
  --output report.pdf
```

Report includes: title page, exec summary, severity/grade card,
scope, methodology, summary table, detailed findings with CVSS
3.1 vector + CWE + remediation + evidence (collapsible), category
appendix. PDF uses reportlab.

---

## 8. Notifier — Slack / generic webhook

Get pinged when critical/high findings land.

### Via env vars (dev)
```bash
export MINERVA_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export MINERVA_WEBHOOK_URL="https://your-server/findings"
export MINERVA_NOTIFY_MIN=high    # critical|high|medium|low
```

### Via API (per-instance, persisted)
```bash
curl -X PUT localhost:5000/api/v1/notifications/config \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"webhook_url":"https://hooks.example.com/minerva",
       "slack_url":"https://hooks.slack.com/...",
       "min_severity":"high"}'

# Fire a test ping
curl -X POST localhost:5000/api/v1/notifications/test \
  -H "Authorization: Bearer $TOKEN"
```

Non-blocking: dispatch runs in a background thread. Findings are
posted as soon as they are created during a campaign.

---

## 9. Plugins & extensibility

### Add a new attack
1. Drop a Python file in `backend/data/pro_attacks/` or
   `backend/data/refined_attacks/` with an `execute(target, params,
   context)` function returning
   `{success, findings, evidence, logs}`.
2. Append a spec entry to the respective `_manifest.json`.
3. `python -m scripts.seed_pro_attacks`.

Every attack gets these helpers for free via `exec_globals`:
`mcp_client`, `oob`, `payloads`, `evidence`, `reverse_shell`,
`mitm_proxy`, `helpers`.

### Add a new scanner plugin
Drop a folder in `backend/plugins/scanners/<id>/` with:
- `plugin.yaml` manifest
- `<engine>.py` defining `execute(target, params, context)`
- `cve_database.yaml` (editable from the admin UI)

See `backend/plugins/scanners/README.md` for the full contract.

### Add a new payload
UI → **Admin → Payloads**, or append to
`backend/app/services/payload_library.py:_SEED` and re-run the seeder.

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| Login works but attack lists empty | Run `python -m scripts.seed_pro_attacks` |
| OOB attacks never confirm | Set `MINERVA_OOB_URL` to a publicly reachable URL; test `curl $MINERVA_OOB_URL/api/v1/callbacks/oob/selftest` returns 204 |
| Reverse-shell RCE never fires | Set `MINERVA_RS_ADVERTISE` to the IP/host the target can dial back to |
| Scanner can't find CVE DB | Ensure `backend/plugins/scanners/client_vuln_scanner/cve_database.yaml` exists; scanner_runner injects `__file__` so it resolves automatically |
| 401 on every request after page refresh | Fixed — ensure `App.jsx` calls `checkAuth()` on mount |
| Port 5432 already in use (Docker) | We remap Postgres to host port 5433 in `docker-compose.yml` |
| PDF export fails | `pip install reportlab==4.0.7` (should already be in requirements) |
| Slack webhook test silent | Check `http_proxy` env; set `MINERVA_NOTIFY_MIN=info` to force-notify |

---

## What's in the box

| Component | Count |
|---|---|
| Active attacks (Pro + Refined) | **44** |
| Core services (mcp_client, oob, reverse_shell, mitm_proxy, ...) | 10 |
| Tagged payloads | 66 |
| Scanner CVE database | 28 CVEs · 12 MCP clients |
| Test assertions | **71** (all green) |
| Report formats | HTML · PDF · JSON · SARIF 2.1.0 |
| MCP transports supported | HTTP · SSE · WebSocket · stdio |
| Auth methods | Bearer · API key · Basic · OAuth2 · Custom |

Documentation:
- `README.md` — overview
- `RUN.md` — this file
- `backend/docs/ARCHITECTURE.md` — system design
- `backend/docs/ATTACKS.md` — attack catalogue
- `backend/docs/PENTEST_WORKFLOW.md` — operator guide
- `backend/docs/REAL_MCP_TARGETS.md` — real MCP servers + ethics
- `backend/plugins/scanners/README.md` — scanner plugin contract
