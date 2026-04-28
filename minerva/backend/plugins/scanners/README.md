# Scanner Plugins

YAML-backed vulnerability scanner plugins. Each plugin lives in its own folder
under `backend/plugins/scanners/<plugin_id>/` and is hot-editable: changes to
`cve_database.yaml` take effect on the next run with no server restart.

## Folder contract

```
<plugin_id>/
  plugin.yaml            # manifest (required)
  <script>.py            # scanner engine (required)
  cve_database.yaml      # editable CVE database (required)
  .backups/              # auto-created; rolling backups of cve_database.yaml
  README.md              # optional; surfaced in the Scanner Detail page
```

- `plugin_id` must match `[a-z0-9_-]+` **and** must equal `plugin.yaml:id`.
- The scanner script must define one of:
  - `execute(target, params, context)`
  - `run(target, params, context)`
  - `scan(target, params, context)`
  and return a dict with keys `{success, findings, evidence, logs}`.

## Execution context

The runner calls the entrypoint with:

- `target`: `{host, port, protocol, base_url}`
- `params`: merged from the user's run form + `plugin.yaml:default_config`
- `context`:
  - `plugin_id`, `plugin_dir`, `cve_db_path` — absolute paths for locating data files
  - `execution_id` — unique id for this run
  - `logger(msg)` — appends a `[SCRIPT] msg` line to the execution log

The runner also sets `__file__` in the exec namespace to the script path. Engines
that resolve sibling data files via `os.path.dirname(os.path.abspath(__file__))`
work unchanged.

## Modules available at runtime

`json, os, re, socket, subprocess, platform, hashlib, datetime, time, requests, yaml, urllib`.

If you need another module, whitelist it in
`backend/app/services/scanner_runner.py:_build_exec_globals`.

## CVE editing from the UI

The admin page at `/admin/scanners` provides structured CRUD for:
- Clients (key, display_name, vendor, type, detection)
- CVEs (identity, versions, description, env_checks, active_checks)
- Globals (dangerous_config_patterns, remote_probe_paths, ws ports, headers)

All writes are atomic (tmp file + `os.replace`) with a rolling backup in
`.backups/`. Restores are exposed via `POST /api/v1/scanners/<id>/restore`.

## Security

- Scanner scripts execute with the Flask process's privileges — **only admins
  should add plugin folders**.
- Admin API endpoints (create/update/delete CVEs/clients/globals, restore) are
  gated with `@admin_required`.
- The run endpoint is `@jwt_required()` and audited.
- YAML writes go through `validate_db` (whole-document) before commit.

## Caveats

- **Comment loss.** PyYAML round-trip strips comments. Switch to `ruamel.yaml`
  if preserving comments matters.
- **Scan locality.** `check_local=true` inspects the Flask server's host, not
  the end user's laptop. Agent-mode for remote scanning is out of scope.
- **Single-process lock.** `yaml_store` uses an in-process lock. For
  multi-worker deployments, add `filelock` for inter-process safety.
