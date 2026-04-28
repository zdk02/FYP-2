# Minerva — Architecture

Minerva is a professional pentesting framework specialised for the
**Model Context Protocol (MCP)** ecosystem. It targets MCP servers,
MCP clients, and the channels between them, across HTTP, SSE, WebSocket
and stdio transports.

## High-level diagram

```
 ┌───────────────────────────────────────────────────────────┐
 │                       Frontend (React)                    │
 │  Dashboard · Targets · Attacks · Scanners · Campaigns     │
 │  · CVE Database admin · Reports                           │
 └──────────────────────────┬────────────────────────────────┘
                            │  REST /api/v1 (JWT)
 ┌──────────────────────────▼────────────────────────────────┐
 │                      Backend (Flask)                       │
 │                                                            │
 │   app/api/        REST routes (attacks, scanners,         │
 │                   callbacks, targets, campaigns, ...)     │
 │                                                            │
 │   app/services/   attack_runner  — shared exec sandbox    │
 │                   mcp_client      — JSON-RPC 2.0 client   │
 │                   oob_callback    — canary tokens         │
 │                   payload_library — DB-backed payloads    │
 │                   evidence        — Finding / Report      │
 │                   scanner_*       — YAML plugin system    │
 │                                                            │
 │   app/models/     SQLAlchemy: Attack, Target, Execution,  │
 │                   Campaign, Payload, ConnectionScript,    │
 │                   AttackExecution, Report, AuditLog, User │
 │                                                            │
 │   plugins/scanners/<id>/   YAML-driven scanners (CVE-     │
 │                            database.yaml + engine.py)     │
 └──────────────────────────┬────────────────────────────────┘
                            │
          ┌─────────────────┼──────────────────┐
          ▼                 ▼                  ▼
       SQLite /           Redis            OOB callback
       Postgres         (Celery)          (inbound only)
```

## Core innovation: **pro-helper injection into every attack**

Every Python attack script is exec'd with the following helpers pre-
injected into its global namespace by
`app/services/attack_runner.build_exec_globals()`:

| Name           | What it is                                             |
| -------------- | ------------------------------------------------------ |
| `mcp_client`   | Full MCP JSON-RPC 2.0 client (HTTP/SSE/WS/stdio, auth) |
| `oob`          | Canary-token out-of-band callback service              |
| `payloads`     | DB-backed payload corpus (tag-queryable)               |
| `evidence`     | `ReportBuilder` + `Finding` dataclass + typed evidence |
| plus `json / re / time / socket / subprocess / yaml / ...`          |

This lets an individual attack stay <300 lines while being truly
professional — no more hand-rolling the MCP protocol or string-matching
response bodies.

## Execution paths

Both entry points share the same `attack_runner.run_python_attack`:

1. **Synchronous** — `POST /api/v1/attacks/:id/test` (the "Test" button).
2. **Asynchronous / campaigns** — `attack_service.AttackExecutor.execute_attack`
   enqueues on a thread pool; the worker thread pushes a Flask app
   context so DB-backed services (payload library, audit log) work.

Legacy bash/ruby/node attacks go through
`attack_runner.run_subprocess_attack` (JSON-in/JSON-out contract).

## Confirmation story

Minerva prefers **side-channel proof** over heuristic pattern matching:

| Layer        | Example                                       | Confidence |
| ------------ | --------------------------------------------- | ---------- |
| Static audit | Zero-width chars in tool description         | high       |
| Pattern      | SQL error text in response                   | high       |
| Diff         | true-vs-false boolean probes differ           | high       |
| Timing       | Baseline + injected sleep delta ≥ N s        | high       |
| **OOB**      | Payload makes target fetch our canary URL    | **confirmed** |

The `oob_callback` service mints a 128-bit token per payload and exposes
a public `POST /api/v1/callbacks/oob/<token>` endpoint. When the target
hits it, the attack unblocks with a list of `{source_ip, timestamp,
headers, body}` — proof that cannot be faked by a local response.

## Data-flow for a single run

1. User creates a **Target** (host, port, protocol, `auth_config`).
2. User selects an **Attack** from the library and presses Run.
3. `test_attack` calls `attack_runner.prepare_target_dict` which merges
   `Target.auth_config` into the dict.
4. `run_python_attack` builds `exec_globals` (pro helpers), exec()s the
   script, calls `execute(target, params, context)`.
5. Attack uses `mcp_client.MCPClient.from_target(target)` to speak MCP.
   Auth is applied transparently.
6. Attack mints OOB tokens if needed, collects findings via
   `evidence.ReportBuilder`, returns
   `{success, findings, evidence, logs, summary}`.
7. Response rendered in the UI; saved to `AttackExecution` row for later
   report generation.

## Scanner plugin architecture (parallel subsystem)

Scanners are YAML-driven, not DB-driven:

```
backend/plugins/scanners/<id>/
  plugin.yaml                  # manifest
  <engine>.py                  # execute(target, params, context)
  cve_database.yaml            # authoritative CVE data
  .backups/<basename>.<ts>.yaml
```

The same `attack_runner` powers scanner execution via
`scanner_runner.py`. All CRUD on `cve_database.yaml` goes through
`yaml_store.py` (atomic write + rolling backup + validation).

## Transports

`mcp_client` auto-detects transport from target fields:

| Target hint                              | Transport chosen   |
| ---------------------------------------- | ------------------ |
| `transport: stdio` or `base_url: stdio:`         | StdioTransport |
| `protocol: ws` / `wss`                   | WebSocketTransport |
| `path: /sse` or `transport: sse`         | SSETransport       |
| everything else                          | HTTPTransport      |

## Authentication

`auth_config` is a dict persisted on `Target.auth_config` (JSON text).
Supported types (UI + backend):

```
{"type": "none"}
{"type": "bearer",  "token": "..."}
{"type": "api_key", "header": "X-API-Key", "value": "..."}
{"type": "basic",   "username": "...", "password": "..."}
{"type": "oauth2",  "token": "..."}     # same as bearer
{"type": "custom",  "headers": {"X-Signature": "..."}}
```

## Evidence & reporting

Every finding now ships with structured evidence (`mcp_call`, `http_request`,
`oob_hit`, `file`, `raw`), timestamps, impact, remediation, CWE refs.
Reports consume this directly.

## Extension points

| Add this…       | Go here                                               |
| --------------- | ----------------------------------------------------- |
| A new attack    | `backend/data/pro_attacks/<name>.py` + manifest entry |
| A new payload   | Admin UI → Payloads, or append to `payload_library`   |
| A new transport | Subclass `mcp_client.Transport`                       |
| A new scanner   | Drop a folder under `backend/plugins/scanners/`       |
