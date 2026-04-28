# Minerva — MCP Pentesting Framework

**A professional penetration-testing framework purpose-built for the
Model Context Protocol (MCP) ecosystem** — clients, servers, and the
transports between them.

16 pro-grade attacks, real JSON-RPC 2.0 across HTTP / SSE / WebSocket /
stdio, out-of-band callback confirmation, reverse-shell proof, active
MITM proxy, YAML-driven CVE scanner, campaign workflow, structured
evidence + reports.

---

## Architecture at a glance

```
 ┌────────────────────────────────────────────────────────────┐
 │ Frontend (React, Vite, Tailwind)                           │
 │  Dashboard · Targets · Attacks · Scanners · Campaigns      │
 │  Reports · CVE DB admin · Auth UI                          │
 └──────────────────────────┬─────────────────────────────────┘
                            │  REST /api/v1 (JWT)
 ┌──────────────────────────▼─────────────────────────────────┐
 │ Backend (Flask + SQLAlchemy + Celery)                      │
 │                                                            │
 │  services/                                                 │
 │    mcp_client       JSON-RPC 2.0  (HTTP/SSE/WS/stdio)      │
 │    oob_callback     Persistent canary tokens (SQLite)      │
 │    reverse_shell    Listener pool, catches real shells     │
 │    mitm_proxy       Active HTTP proxy, records flows       │
 │    payload_library  66+ tagged payloads (SQL/cmd/RCE/...)  │
 │    evidence         Finding + ReportBuilder + evidence     │
 │    attack_runner    Shared exec sandbox (Test + Campaigns) │
 │    scanner_*        YAML-driven CVE scanner engine         │
 │                                                            │
 │  data/pro_attacks/  16 Pro Python attack scripts           │
 │  plugins/scanners/  YAML-based scanner plugins             │
 │  scripts/           demo_mcp_server, seed_pro_attacks      │
 │  tests/             E2E + unit tests (43 assertions)       │
 └──────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  SQLite / Postgres   Redis (Celery)      OOB catcher
                                          (public HTTP)
```

---

## Pro attack catalogue (16 active)

| # | Attack                                   | Category         | Confirmation      |
|---|------------------------------------------|------------------|-------------------|
|  1| Direct Prompt Injection (Pro)            | Client           | Canary echo       |
|  2| Indirect Prompt Injection (Pro)          | Client           | Canary + resource audit |
|  3| Tool Poisoning (Pro)                     | Client           | Static audit      |
|  4| Tool Shadowing & TOCTOU (Pro)            | Client           | Fingerprint diff  |
|  5| Tool Rebinding (Pro)                     | Client           | Mid-session drift |
|  6| LLM Jailbreak (Pro)                      | Client           | Canary + marker   |
|  7| Command Injection (Pro)                  | Server           | Timing + OOB      |
|  8| SQL Injection (Pro)                      | Server           | Error + bool + time |
|  9| Remote Code Execution (Pro)              | Server           | OOB + reverse-shell |
| 10| SSRF (Pro)                               | Server           | OOB + cloud-meta  |
| 11| Path Traversal / LFI (Pro)               | Server           | Canonical marker  |
| 12| Authentication Bypass (Pro)              | Server           | 4-phase compare   |
| 13| Resource Exhaustion / DoS (Pro)          | Server           | Acceptance checks |
| 14| Information Disclosure (Pro)             | Server           | Multi-surface     |
| 15| Insecure Deserialization (Pro)           | Server           | OOB + canary      |
| 16| MCP MITM & Data-in-Transit Posture (Pro) | Data-in-Transit  | TLS + leak scan   |

The 28 original simulation-grade attacks are retained in the database
(`is_active=False`) for before/after comparison in the FYP writeup.

---

## Quickstart — native dev (2 minutes)

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m scripts.seed_pro_attacks   # first-time only
python run.py                         # → http://localhost:5000

# Frontend (second terminal)
cd frontend
npm install
npm run dev                           # → http://localhost:5173
```

Log in as `admin@minerva.local / admin123` (SQLite) or
`admin@aegis.local / admin123` (existing installations).

## Quickstart — Docker

```bash
docker compose up -d --build
# Seed pro attacks inside the container
docker exec -it aegis-backend python -m scripts.seed_pro_attacks
# Open http://localhost
```

---

## FYP demo (90 seconds)

Three terminals:

```bash
# T1 — the deliberately-vulnerable target (9 tools, all vulnerable)
cd backend
python -m scripts.demo_mcp_server --port 8765

# T2 — the framework
python run.py

# T3 — automated proof-of-exploit
python -m tests.test_pro_attacks_e2e
python -m tests.test_core_services
```

Then in the UI:

1. **Targets → + Add Target** · host `127.0.0.1`, port `8765`,
   protocol `http`, auth `None` → **Save**.
2. Click **Test Connection** → toast: "MCP OK — minerva-demo · 10 tools".
3. **Attacks → Direct Prompt Injection (Pro) → Test** → pick that
   target → **Run**. 3 confirmed findings in ~3 seconds.
4. Try **Insecure Deserialization (Pro)** — confirmed RCE via pickle OOB.
5. Try **Command Injection (Pro)** — confirmed blind injection via OOB.
6. **Admin → CVE Database** — inspect the 12-client / 28-CVE scanner.

## Test results (verifiable, reproducible)

```
11 / 11   backend/tests/test_pro_attacks_e2e.py    # attacks vs. vuln target
32 / 32   backend/tests/test_core_services.py       # unit tests
```

Both test suites run in under 30 seconds and are fully deterministic
(no external calls).

---

## What makes this professional, not academic

### Real MCP protocol — not HTTP-with-JSON
`app/services/mcp_client.py` speaks the MCP 2024-11-05 spec:
- `initialize → initialized → tools/list → tools/call → resources/read
  → prompts/list → ping → completion/complete → logging/setLevel`
- Four transports: HTTP POST, SSE streaming, raw WebSocket
  (RFC 6455 handshake), stdio subprocess
- Auth: Bearer, API key, HTTP Basic, OAuth2, custom headers
- Uniform response shape so attacks never crash on bad servers

### Side-channel proof — not response-text guessing
Blind exploits are confirmed with side-channel signals that no amount
of response filtering can fake:

| Service          | Proves                                                   |
|------------------|----------------------------------------------------------|
| **oob_callback** | Payload makes target hit our canary URL → callback dict  |
| **reverse_shell**| Payload makes target connect back → live TCP + stdout    |
| **mitm_proxy**   | MCP traffic routed through us → full JSON-RPC flow capture |

All persisted to SQLite so restarts don't lose confirmation state.

### Structured evidence — audit-trail quality
Every finding ships with:
- `severity`, `confidence`, `category`, `cwe`, `cve?`
- `tool`, `parameter`, `payload`
- `description`, `impact`, `remediation`, `references[]`
- `evidence[]` — typed entries: `mcp_call`, `http_request`, `oob_hit`,
  `file`, `raw`
- `timestamp`, `duration_ms`, deterministic `id`

### Unified execution — Test button == Campaigns
`attack_runner.run_python_attack` is the single execution path. In-
process exec for Python (with all pro helpers pre-injected), subprocess
fallback for bash/ruby/node. Timeouts are enforced via
`ThreadPoolExecutor`. Flask app context is pushed into the worker
thread so DB-backed services (payload lookup, audit log) work.

### YAML-driven scanner plugins
The `client_vuln_scanner` plugin audits 12 MCP clients against 28+
CVEs. Three-layer verification: version correlation → env checks →
active probes. Admin UI lets you add/edit CVEs directly in YAML —
writes are atomic with rolling backups.

---

## Auth and deployment

Each Target carries an `auth_config`. Attacks honour it transparently:

```json
{"type": "bearer",  "token": "eyJhbGci..."}
{"type": "api_key", "header": "X-API-Key", "value": "sk-..."}
{"type": "basic",   "username": "u", "password": "p"}
{"type": "custom",  "headers": {"X-Signature": "..."}}
```

For OOB callbacks to work against external targets, set
`MINERVA_OOB_URL` to a publicly reachable base URL:

```bash
export MINERVA_OOB_URL=https://pentest.example.com
# or, behind NAT:
ngrok http 5000    # then use the ngrok URL
```

For reverse-shell confirmation, set `MINERVA_RS_ADVERTISE` to the host
the target should dial back to.

---

## Documentation

- `RUN.md` — **one-page complete run guide** (native · docker · lab · tests · reports · notifier)
- `backend/docs/ARCHITECTURE.md` — system design + data flow
- `backend/docs/ATTACKS.md` — per-attack CWE / confirmation details
- `backend/docs/PENTEST_WORKFLOW.md` — operator guide (public / LAN /
  stdio / mTLS / enterprise)
- `backend/docs/REAL_MCP_TARGETS.md` — curated real MCP servers to test + ethics
- `backend/plugins/scanners/README.md` — scanner plugin contract

---

## Safety & authorisation

**This is offensive tooling.** Use only against systems you own or have
explicit written authorisation to test. The framework includes active
exploit primitives (command injection, RCE, reverse-shell listener,
SSRF) — they are powerful by design. `scripts/demo_mcp_server.py` is
the only safe target shipped with the project and is meant for
closed-network demos only.

---

## Credits

Built as a Final-Year Project. Core engine, attack catalogue, scanner
plugin system, demo server, integration + unit test suites, and
documentation authored during the project. Based on the AEGIS
platform scaffold (Flask + React + Celery + SQLAlchemy).
