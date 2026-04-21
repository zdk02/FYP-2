# AEGIS Plugin: MCP Client Vulnerability Scanner v3.0

## Architecture: Multi-Layer Verification

```
┌────────────────────────────────────────────────────────────────────┐
│                     cve_database.yaml                              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │   clients    │  │   CVEs +     │  │ dangerous_config_patterns│  │
│  │  detection   │  │  env_checks  │  │ remote_probe_paths       │  │
│  │   rules      │  │ active_checks│  │ websocket_probe_ports    │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────┬─────────────┘  │
│         └─────────────┬───┘                       │                │
└───────────────────────┼───────────────────────────┘                │
                        ▼                                            │
┌────────────────────────────────────────────────────────────────────┘
│              client_vuln_scanner.py  (Pure engine)
│
│  Layer 0: DETECTION
│    Process enumeration → Config path discovery → Version commands
│
│  Layer 1: VERSION CORRELATION
│    Compare detected version against affected_versions
│    Result: confidence = "medium" (known ver) or "low" (unknown ver)
│
│  Layer 2: ENVIRONMENT CHECKS  (from YAML env_checks)
│    Verify conditions that make CVE exploitable
│    e.g. "is .mcp.json present?", "is Workspace Trust off?"
│    Result: bumps confidence to "high"
│
│  Layer 3: ACTIVE VERIFICATION  (from YAML active_checks)
│    Non-destructive probes that prove vulnerability exists
│    e.g. "connect to WebSocket without auth", "is YOLO mode on?"
│    Result: bumps confidence to "confirmed"
│
│  Each finding gets: [SEVERITY] + [CONFIDENCE]
│  Users can filter by both: --min-severity high --min-confidence medium
└────────────────────────────────────────────────────────────────────
```

## Why v3 > v2

| Feature | v2 | v3 |
|---------|----|----|
| Version matching | ✓ | ✓ |
| Environment context | ✗ | ✓ (YAML `env_checks`) |
| Active verification | ✗ | ✓ (YAML `active_checks`) |
| Confidence scoring | ✗ | ✓ (confirmed/high/medium/low) |
| Filter by confidence | ✗ | ✓ (`min_confidence` param) |
| Per-CVE check detail | ✗ | ✓ (evidence shows which checks passed/failed) |

## Check Types Available in YAML

| Type | What it does | Example |
|------|-------------|---------|
| `file_exists` | Check if path exists | `{ path: "~/.claude/" }` |
| `dir_exists` | Check if directory exists | `{ path: ".cursor/" }` |
| `file_contains` | Regex match in file content | `{ path: "settings.json", pattern: "autoApprove" }` |
| `file_not_contains` | Verify pattern is absent | `{ path: "...", pattern: "dangerous" }` |
| `port_open` | TCP connect check | `{ host: "127.0.0.1", port: 3000 }` |
| `ws_no_auth` | WebSocket handshake without auth | `{ host: "127.0.0.1", port: 3000 }` |
| `http_probe` | HTTP request + status check | `{ url: "http://...", expect_status: [200] }` |
| `http_header` | Check response header exists | `{ url: "...", header: "x-mcp-version" }` |
| `command_output` | Run command + match output | `{ cmd: "which sed", expect_pattern: "/sed" }` |
| `config_json_value` | Parse JSON + check key value | `{ path: "...", key: "dotted.key", expect: "true" }` |
| `npm_installed` | Check npm package version | `{ package: "...", vulnerable_below: "2.0.31" }` |
| `process_running` | Check if process exists | `{ name: "claude" }` |
| `tcp_banner` | Grab TCP banner + regex match | `{ host: "...", port: 8080, expect: "MCP" }` |

**To add a new check type:** Add a `_check_typename` method to the `CheckEngine` class. That's it.

## Quick Start

```bash
pip install pyyaml requests
python client_vuln_scanner.py
```

## Adding a CVE with Verification Checks

```yaml
      - id: "CVE-2099-XXXXX"
        title: "My New Vulnerability"
        severity: critical
        cvss: 9.8
        affected_versions: "< 5.0.0"
        fixed_version: "5.0.0"
        description: "What it does."
        remediation: "How to fix."

        env_checks:
          - type: file_exists
            path: ".dangerous/config.json"
            description: "Dangerous config file is present"
          - type: command_output
            cmd: "python3 -c \"import sys; print(sys.platform)\""
            expect_pattern: "win32"
            description: "Only exploitable on Windows"

        active_checks:
          - type: port_open
            host: "127.0.0.1"
            port: 9999
            description: "Vulnerable service port is exposed"
          - type: ws_no_auth
            host: "127.0.0.1"
            port: 9999
            description: "Service accepts unauthenticated WebSocket"
```

## Coverage (2026-04-07)

**12 clients · 28 CVEs · 13 check types · All verified from real sources**
