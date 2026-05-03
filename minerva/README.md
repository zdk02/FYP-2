# Minerva — Professional MCP Pentesting Framework

**An industry-grade penetration-testing framework purpose-built for the
Model Context Protocol (MCP) ecosystem** — clients, servers, and the
transports between them.

24 pro-grade attacks covering every documented MCP attack surface, real
JSON-RPC 2.0 across HTTP / SSE / WebSocket / stdio, side-channel
confirmation (OOB / reverse-shell / MITM), structured evidence, signed
audit log, engagement scope enforcement, SARIF + compliance-mapped
reports, and four-role RBAC.

---

## What makes Minerva pro-grade

Most "MCP security" tooling is HTTP-with-JSON pretending to be MCP, with
detection logic that grep-matches response bodies. Minerva does the
real protocol, confirms blind bugs with side channels, and enforces the
operational rigour pro firms need to deploy a pentesting tool in front
of paying customers.

**Real protocol.** `app/services/mcp_client.py` speaks MCP 2024-11-05
through 2025-06-18: `initialize → initialized → tools/list →
tools/call → resources/read → resources/subscribe → prompts/list →
prompts/get → completion/complete → sampling/createMessage →
elicitation/create → ping → logging/setLevel`. Four transports
(HTTP POST, SSE streaming, raw WebSocket via RFC 6455 handshake, stdio
subprocess). All auth schemes (Bearer, API key, HTTP Basic, OAuth2,
custom headers).

**Side-channel proof, not response-text guessing.** Blind exploits are
confirmed with three independent side channels:

| Service | Proves |
|---|---|
| `oob_callback` | Payload makes target hit our canary URL → callback dict with source-IP / method / path |
| `reverse_shell` | Payload makes target connect back → live TCP + captured stdout |
| `mitm_proxy` | MCP traffic routed through us → full JSON-RPC flow capture |

All persisted to SQLite so restarts don't lose confirmation state.

**Structured evidence.** Every finding ships with `severity`,
`confidence`, `category`, `cwe`, `cve`, `cvss_v31_vector`,
`cvss_v40_vector`, `tool`, `parameter`, `payload`, `description`,
`impact`, `remediation`, `references[]`, typed `evidence[]` entries
(`mcp_call`, `http_request`, `oob_hit`, `file`, `raw`), `timestamp`,
`duration_ms`, deterministic `id`, and a `compliance_map` linking it
to OWASP LLM Top-10 (2025), MITRE ATLAS, MITRE ATT&CK, CWE, and NIST
AI RMF.

**Engagement-scoped execution.** No attack runs against a target
unless that target is in the active Engagement's authorized allowlist,
the time window is open, the request budget is not exhausted, and the
engagement is not killed. The pre-flight gate is in
`attack_runner.preflight_check` and is the same check for the synchronous
Test button and the asynchronous Campaign runner.

**Tamper-evident audit log.** Every login, attack run, finding event,
and report export is hash-chained (`prev_hash` / `entry_hash` over
SHA-256). The chain is verifiable end-to-end via
`audit_service.verify_chain()` — surfaceable in Admin UI.

**Four-role RBAC.** `admin` (everything), `operator` (run attacks,
manage engagements), `analyst` (review findings, mark FP, no execution),
`viewer` (read-only). Decorators on every API endpoint.

---

## Pro attack catalogue (24 active)

| # | Attack | Category | Confirmation |
|---|---|---|---|
|  1| Direct Prompt Injection | Client | Canary echo |
|  2| Indirect Prompt Injection | Client | Canary + resource audit |
|  3| Tool Poisoning | Client | Static + active call |
|  4| Tool Shadowing & TOCTOU | Client | Fingerprint diff across snapshots |
|  5| Tool Rebinding | Client | Functional TOCTOU race |
|  6| LLM Jailbreak | Client | Canary + unsafe-marker co-occurrence |
|  7| Sampling Abuse | Client | Reverse `sampling/createMessage` probe |
|  8| Elicitation Abuse | Client | Reverse `elicitation/create` probe + sensitive-field detection |
|  9| Tool Annotations Spoofing | Client | `readOnlyHint` / `destructiveHint` honesty check via state-drift fingerprint |
| 10| Command Injection | Server | Timing + OOB callback + adaptive encoding bypass |
| 11| SQL Injection | Server | Error + boolean + per-dialect time-based + WAF bypass |
| 12| Remote Code Execution | Server | OOB + reverse-shell + SSTI + Log4Shell JNDI |
| 13| SSRF | Server | OOB + cloud-meta (AWS IMDSv2 / GCP / Azure / OCI / K8s SA / Docker / etcd) |
| 14| Path Traversal / LFI | Server | Canonical marker + adaptive encoding bypass |
| 15| Authentication Bypass | Server | Auth/no-auth/bad-token compare + JWT alg=none / kid SQLi / weak-HMAC |
| 16| Authorization Horizontal (BOLA/IDOR) | Server | Two-principal cross-access verification |
| 17| OAuth 2.1 Flow Attacks | Server | `.well-known` audit + PKCE / state / redirect / audience / scope tests |
| 18| Resource Exhaustion / DoS | Server | Concurrency burst + ReDoS + amplification (non-destructive) |
| 19| Information Disclosure | Server | Multi-surface + secret validation against issuer |
| 20| Insecure Deserialization | Server | Pickle / YAML / Java / .NET — OOB-confirmed |
| 21| Prompts Argument Injection | Server | Canary + SSTI engines (Jinja/Velocity/Handlebars/Mustache/EL/Razor/Twig) |
| 22| Stdio Argv / Env Injection | Server | Argv splitting + shell expansion + `/proc/self/environ` |
| 23| Schema Type Confusion | Server | Wrong-type / overflow / deep nesting / oneOf confusion |
| 24| Pagination Cursor Abuse | Server | SQLi / SSRF / traversal / oversized cursor across `*/list` methods |
| 25| Protocol Version Downgrade | Server | Deprecated-version / bogus-version / re-init / batch acceptance |
| 26| Notifications & Subscription Abuse | Server | `resources/subscribe` flood + malformed notification + hijack |
| 27| Logging setLevel Abuse | Server | Unauthenticated `logging/setLevel` + verbose-leak observation |
| 28| WebSocket Transport Hardening | Data-in-Transit | Origin / subprotocol / fragmentation / large-frame handling |
| 29| HTTP Session Hardening | Data-in-Transit | Cookie flags + session fixation + predictable IDs |
| 30| MCP MITM & Data-in-Transit Posture | Data-in-Transit | Plain-HTTP / TLS chain / cipher / HSTS / leak scan |

(Numbering reflects manifest order; categories are the three MCP attack
surfaces — Client, Server, Data-in-Transit.)

The 28 original simulation-grade attacks are retained in the database
(`is_active=False`) for before/after comparison.

---

## Operational rigour (the pro-grade parts)

### Engagements — legal scope enforcement

Every attack run is bound to an `Engagement`. An Engagement records:

- **name** + **client name** + **signed-off-by** (legal authorization)
- **authorized_targets** — list of host/CIDR allowlist patterns; the
  pre-flight gate **hard-rejects** any target outside this list with no
  override
- **time_window_start / time_window_end** — runs outside the window
  are rejected
- **max_requests** — token-bucket budget; exceeded = run aborts mid-flight
- **safe_mode** — disables RCE / reverse-shell / destructive
  deserialization / DoS payloads at the runner level (not just by
  convention)
- **dry_run_default** — when set, attacks log payloads but never send
  them; useful for examiner walk-throughs and SOC2 audit demos
- **is_killed** — global kill switch flag; checked between iterations
- **sow_filename / sow_path** — Statement of Work upload (PDF/DOCX),
  retained as forensic evidence of authorization

The active-engagement banner (red **OUT-OF-SCOPE** vs. green
**AUTHORIZED**) is visible on every page of the UI.

### Audit log — tamper-evident

Every action — login, attack started/stopped, finding created, finding
dismissed, FP marked, payload sent, OOB callback received, report
exported, engagement modified, settings changed — is appended to
`audit_logs` with `prev_hash` linking it to the previous entry (chain
seeded from the application secret).

`audit_service.verify_chain()` walks the chain and reports any break —
surfaceable in Admin → Audit Log → "Verify integrity".

### Safety / blast-radius controls

- **Dry-run mode** — per-engagement default + per-run override.
  Payloads are logged with full detail, but `mcp_client.call` is
  short-circuited.
- **Safe mode** — disables attack categories tagged `destructive`
  (`reverse_shell`, `dos`, `pickle_rce`). The runner enforces this; the
  attack scripts can't override.
- **Per-engagement quotas** — max requests, max wall time, max
  concurrent attacks. Counters persisted on the Engagement.
- **Target health probe** — latency baseline established at
  Engagement-creation; abort the run if mid-flight latency exceeds
  `health_threshold_x` × baseline (default 3×). Avoids being the reason
  a customer's prod fell over during an authorized test.
- **Global kill switch** — UI button → sets `Engagement.is_killed=True`
  → all in-flight runs check this between iterations and abort within
  the next request boundary.

### Findings hygiene

- **Cross-run dedup** keyed on `(engagement_id, target, tool,
  parameter, payload_class)`. Re-running the same attack produces a
  diff, not duplicates.
- **Mark as false-positive / accepted-risk / fixed** — operator can
  curate findings; status is remembered across runs of the same
  engagement.
- **Diff report** between any two campaign runs in the same engagement:
  *N new criticals, M fixed, K regressed*. UI button on Reports page.
- **Confidence model** — each `(attack, payload-class)` pair tracks
  historical FP rate; new findings inherit a confidence adjustment.

### Replay & manual mode

- **Replay** — every finding has a one-click *Reproduce* button that
  re-runs the exact `mcp_call` with the same params and records new
  evidence under the original finding ID. Verifies a fix or confirms
  reproducibility for the report.

### Reporting

- **SARIF 2.1.0** export — table-stakes integration format (GitHub
  Advanced Security, GitLab, Azure DevOps consumers).
- **Compliance mapping** — every finding pre-mapped to OWASP LLM
  Top-10 (2025), MITRE ATLAS, MITRE ATT&CK, CWE, NIST AI RMF. Reports
  filterable by framework.
- **Four templates** — Executive (1-page, no tech), Technical (full
  evidence + repro steps + CVSS vectors), Compliance (mapped to a
  selected framework), Diff (between two campaign runs).
- **CVSS v3.1 + v4 vector strings** — not just keyword severity.
  Surfaced in finding detail UI and report sections.
- **Customisable Jinja templates** — drop a `.j2` into
  `backend/data/report_templates/` for branded output.

### RBAC

| Role | Run attacks | Modify engagements | Review findings | Mark FP | Admin |
|---|---|---|---|---|---|
| `admin` | yes | yes | yes | yes | yes |
| `operator` | yes | yes | yes | yes | no |
| `analyst` | no | no | yes | yes | no |
| `viewer` | no | no | yes | no | no |

All API endpoints carry `@role_required(...)`. UI hides controls the
role can't reach.

### Notifications

`app/services/notifier.py` handles webhooks. Configurable per-engagement:

- **Generic webhook** — POST signed JSON; HMAC-SHA256 over the body
  using the engagement's `webhook_secret`. Header
  `X-Minerva-Signature: sha256=<hex>`.
- **Slack** — incoming-webhook formatted card.
- **Teams** — Adaptive Card payload.
- Severity threshold per channel.

---

## Quickstart

### Native dev (2 minutes)

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m scripts.seed_pro_attacks           # first-time only
python -m scripts.seed_default_engagement    # creates the FYP Demo engagement
python run.py                                # → http://localhost:5000

# Frontend (second terminal)
cd frontend
npm install
npm run dev                                  # → http://localhost:5173
```

Default credentials:
- `admin@minerva.local / admin123` (admin)
- `operator@minerva.local / operator123` (operator)
- `analyst@minerva.local / analyst123` (analyst)
- `viewer@minerva.local / viewer123` (viewer)

### Docker

```bash
docker compose up -d --build
docker exec -it aegis-backend python -m scripts.seed_pro_attacks
docker exec -it aegis-backend python -m scripts.seed_default_engagement
# Open http://localhost
```

---

## FYP demo (90 seconds)

Three terminals:

```bash
# T1 — the deliberately-vulnerable target (24 vulnerable tools)
cd backend
python -m scripts.demo_mcp_server --port 8765

# T2 — the framework
python run.py

# T3 — automated proof-of-exploit
python -m tests.test_pro_attacks_e2e
python -m tests.test_core_services
```

Then in the UI:

1. Confirm the green **AUTHORIZED** banner shows the active engagement
   ("FYP Demo") with `127.0.0.1` / `localhost` allowlisted.
2. **Targets → + Add Target** · host `127.0.0.1`, port `8765`,
   protocol `http`, auth `None` → **Save**.
3. Click **Test Connection** → toast: "MCP OK — minerva-demo · N tools".
4. **Attacks → Direct Prompt Injection → Test** → pick the target →
   **Run**. 3 confirmed findings in ~3 seconds.
5. Try **Tool Annotations Spoofing** — confirms `readOnlyHint` lying.
6. Try **Authorization Horizontal** — confirms BOLA via two-principal
   compare.
7. Try **Insecure Deserialization** — confirmed RCE via pickle OOB.
8. **Reports → New → SARIF** — exports `findings.sarif` ready for
   GitHub/GitLab.
9. **Admin → Audit Log → Verify integrity** — confirms the hash chain
   is intact.

## Test results

```
13 / 13   backend/tests/test_pro_attacks_e2e.py    # attacks vs. vuln target
36 / 36   backend/tests/test_core_services.py       # unit tests
 5 /  5   backend/tests/test_engagement_scope.py    # scope-gate enforcement
 3 /  3   backend/tests/test_audit_chain.py         # tamper-evident chain
```

All test suites run in under 60 seconds and are fully deterministic
(no external calls).

---

## Architecture

```
 ┌────────────────────────────────────────────────────────────┐
 │ Frontend (React, Vite, Tailwind)                           │
 │  Engagements · Targets · Attacks · Scanners · Campaigns    │
 │  Reports (SARIF export) · CVE DB · Audit Log · Auth UI     │
 │  Active-engagement banner · Replay · FP triage             │
 └──────────────────────────┬─────────────────────────────────┘
                            │  REST /api/v1 (JWT + RBAC)
 ┌──────────────────────────▼─────────────────────────────────┐
 │ Backend (Flask + SQLAlchemy + Celery)                      │
 │                                                            │
 │  services/                                                 │
 │    mcp_client       JSON-RPC 2.0  (HTTP/SSE/WS/stdio)      │
 │    oob_callback     Persistent canary tokens               │
 │    reverse_shell    Listener pool, catches real shells     │
 │    mitm_proxy       Active HTTP proxy, records flows       │
 │    payload_library  66+ tagged payloads                    │
 │    evidence         Finding + ReportBuilder                │
 │    attack_runner    Pre-flight gate + scope enforcement    │
 │    engagement_service  Scope, quotas, kill switch          │
 │    audit_service    Hash-chained tamper-evident log        │
 │    sarif_exporter   SARIF 2.1.0 emission                   │
 │    compliance       OWASP/ATLAS/ATT&CK/NIST mapping        │
 │    cvss             v3.1 + v4 vector calculation           │
 │    notifier         Webhook + Slack + Teams                │
 │    scanner_*        YAML-driven CVE scanner                │
 │                                                            │
 │  data/pro_attacks/  30 pro-grade Python attack scripts     │
 │  data/compliance_mapping.json    Per-attack framework map  │
 │  data/report_templates/          Jinja templates           │
 │  plugins/scanners/  YAML-based scanner plugins             │
 │  scripts/           demo_mcp_server, seeders               │
 │  tests/             E2E + unit + scope + chain (57 tests)  │
 └──────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  SQLite / Postgres   Redis (Celery)      OOB catcher
                                          (public HTTP)
```

---

## Documentation

- `RUN.md` — one-page complete run guide
- `backend/docs/ARCHITECTURE.md` — system design + data flow
- `backend/docs/ATTACKS.md` — per-attack CWE / confirmation details
- `backend/docs/ENGAGEMENTS.md` — engagement scope + safety guide
- `backend/docs/PENTEST_WORKFLOW.md` — operator guide
- `backend/docs/REAL_MCP_TARGETS.md` — curated real MCP servers + ethics
- `backend/plugins/scanners/README.md` — scanner plugin contract

---

## Safety & authorisation

**This is offensive tooling.** Use only against systems explicitly
authorised by the active Engagement's signed-off scope. The framework
includes active exploit primitives (command injection, RCE,
reverse-shell, SSRF) and refuses to run them outside scope, but it
cannot vet whether your scope authorisation is itself valid — that's a
human responsibility. `scripts/demo_mcp_server.py` is the only safe
target shipped with the project.

---

## Credits

Built as a Final-Year Project. Core engine, attack catalogue,
engagement-scope enforcement, audit chain, scanner plugin system, demo
server, integration + unit test suites, and documentation authored
during the project. Built on the AEGIS platform scaffold (Flask + React
+ Celery + SQLAlchemy).
