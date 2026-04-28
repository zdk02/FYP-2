# Minerva — Pro Attack Catalogue

All 12 active attacks are `*(Pro)` versions. Legacy simulation attacks
are preserved in the database (`is_active=False`) for the FYP
comparative writeup; they are hidden in the UI.

Every Pro attack:

- Speaks real MCP JSON-RPC 2.0 via `mcp_client.MCPClient`
- Uses `Target.auth_config` transparently
- Returns structured findings via `evidence.ReportBuilder`
- Prefers side-channel OOB confirmation over heuristic matching
- Handles timeouts, broken servers, and missing tools gracefully

## Client-Side Attacks (5)

### Direct Prompt Injection (Pro)
Canary-verified injection against every string tool-argument. Each
payload embeds a UUID; finding confidence is `confirmed` only if the
canary appears in the tool's response.
CWE-77 · Severity: **Critical**

### Indirect Prompt Injection (Pro)
Reads every MCP resource and tests tool-output echoing. Reports
resources that carry directives + tools that reflect attacker-
controlled text back into the context window.
CWE-77 · Severity: **Critical**

### Tool Poisoning (Pro)
Static audit of all MCP metadata (tool names, descriptions, parameter
descriptions, prompt / resource fields) for:
- Zero-width Unicode smuggling
- Hidden HTML comments
- "Ignore previous instructions" / "You are now DAN" / role-switch
- Fake deprecation banners
- Shell commands embedded in descriptions
CWE-94, CWE-1007 · Severity: **High**

### Tool Shadowing & TOCTOU (Pro)
N-sample `tools/list` fingerprinting. Detects:
- Normalised-name collisions ("read_file" vs "Read_File")
- Description collisions
- Drift between snapshots
CWE-1023, CWE-367 · Severity: **High**

### Tool Rebinding (Pro)
Functional TOCTOU race: list → exercise → list again. Flags tools that
appear / disappear / mutate mid-session — MCP equivalent of DNS
rebinding.
CWE-367 · Severity: **High**

## Server-Side Attacks (6)

### Command Injection (Pro)
Baseline-normalised timing probes **plus** OOB callback confirmation.
Picks candidate tools by name/description keywords; forcible via
`only_tool_names`.
CWE-78 · Severity: **Critical**

### SQL Injection (Pro)
Three layers — error-based, boolean-based (true/false response diff),
and DB-dialect time-based (MySQL / Postgres / MSSQL / Oracle). Confidence
escalates per layer.
CWE-89 · Severity: **Critical**

### Remote Code Execution (Pro)
OOB-confirmed RCE against eval/exec-style tools. Python, Node, PHP and
Ruby payload variants. Timing fallback for egress-blocked environments.
CWE-94 · Severity: **Critical**

### SSRF (Pro)
Canary URL injection with OOB confirmation, plus cloud-metadata probes
(AWS IMDS v1/v2, GCP metadata, Azure MSI). Confirmed + impact.
CWE-918 · Severity: **High**

### Path Traversal / LFI (Pro)
Canonical marker matching (root:x:0:0:, SSH keys, Windows hosts file)
via classic + encoded + double-dot bypass payloads.
CWE-22 · Severity: **High**

### Authentication Bypass (Pro)
4-phase comparison — authenticated / no-auth / bad-token /
per-tool-no-auth. Flags missing auth, arbitrary-token acceptance, token
oracles (error-text leaks), and sensitive-tool bypass.
CWE-287, CWE-306, CWE-862 · Severity: **Critical**

## Data-in-Transit (1)

### MCP MITM & Data-in-Transit Posture (Pro)
Enterprise-grade transit audit:
- Plain-HTTP accessibility probe
- TLS version / cipher / cert-expiry inspection
- HSTS presence
- Tool-response secret-leakage scan (API keys, cloud creds, tokens)
CWE-319, CWE-326, CWE-295, CWE-532 · Severity: **High**

## How to add a new attack

1. Create `backend/data/pro_attacks/<name>.py` with
   `def execute(target, params, context) -> dict` returning
   `{success, findings, evidence, logs}`.
2. Append an entry to `backend/data/pro_attacks/_manifest.json`.
3. Run `python -m scripts.seed_pro_attacks`.
4. Attack appears immediately in the UI.

See any existing Pro attack for the idiomatic shape.

## Test matrix

The file `backend/tests/test_pro_attacks_e2e.py` spins up the
deliberately-vulnerable demo MCP server at a random port and runs every
Pro attack against it, asserting the expected category of finding is
produced. Current pass rate: **7/7** smoke tests (remaining attacks
require live credential / live cloud / TLS-enabled servers to assert on
and are tested manually).
