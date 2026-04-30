# Unit Testing — Minerva (Backend + Frontend)

**Session 1 of 10** in the Minerva FYP testing programme.

---

## What is Unit Testing?

Unit testing verifies that the **smallest individually testable parts**
of the system — usually pure functions, single classes, or stores —
produce the correct output for a given input. Unit tests run with **no
database, no network, no real browser, no Flask context**. They are
fast, deterministic, and pinpoint exactly where a regression was
introduced.

The Minerva codebase is split into a Python (Flask) **backend** and a
React **frontend**. Both layers are unit-tested independently.

---

# Part A — Backend (Python · pytest)

## Scope

We targeted five pure-function modules in `backend/app/services/`:

| Module                  | What it does                                              |
|-------------------------|-----------------------------------------------------------|
| `mcp_client.apply_auth` | Composes HTTP headers from a Target's auth_config         |
| `cvss`                  | Derives CVSS 3.1 scores, dedupes findings, grades risk    |
| `evidence`              | Builds structured Finding + Evidence objects               |
| `cve_schema`            | Validates scanner-plugin YAML CVE entries                  |
| `attack_helpers`        | Schema-walking helpers used by every refined attack        |

## Test inventory (89 tests)

| File                              | Tests | What it proves                                       |
|-----------------------------------|------:|------------------------------------------------------|
| `tests/unit/test_mcp_client_auth.py`         |    20 | All 5 auth types compose correct headers; bad input is handled gracefully |
| `tests/unit/test_cvss_scoring.py`            |    24 | Category → CVSS mapping, confidence cap, dedupe, A-F grading |
| `tests/unit/test_evidence_builders.py`       |    14 | Findings have stable shape; evidence builders normalise input |
| `tests/unit/test_cve_schema_validation.py`   |    16 | Malformed YAML is rejected with clear errors         |
| `tests/unit/test_attack_helpers.py`          |    15 | Schema helpers correctly parse MCP tool definitions   |
| **Total**                                     | **89** |                                                      |

## How to run

From `minerva/backend/`:

```bash
# Run all backend unit tests with HTML report
python -m pytest tests/unit/ -m unit \
  --html=reports/tests/unit_test_report.html --self-contained-html

# Run a single file
python -m pytest tests/unit/test_cvss_scoring.py -v

# Run a single test
python -m pytest tests/unit/test_cvss_scoring.py::TestRiskGrade::test_grade_boundaries -v
```

## Latest result

```
============================= 89 passed in 3.82s ==============================
```

**Pass rate:** 89 / 89 (100%)
**Wall-clock:** 3.82 seconds
**HTML report:** `backend/reports/tests/unit_test_report.html`

---

# Part B — Frontend (React · Vitest)

## Scope

We targeted the auth state store and the API client interceptor — the
two places where pure logic lives in the frontend (everything else is
either UI rendering or network I/O, which belong in component / system
tests later).

| Module                  | What it does                                              |
|-------------------------|-----------------------------------------------------------|
| `stores/authStore.js`   | Zustand store holding user, tokens, role helpers          |
| `services/api.js`       | Axios instance with timeout-bumping request interceptor   |

## Test inventory (29 tests)

| File                                | Tests | What it proves                                       |
|-------------------------------------|------:|------------------------------------------------------|
| `tests/unit/authStore.test.js`      |    15 | `hasRole`, `isAdmin`, `isManager`; login success / failure / logout state transitions; `updateUser` merge; `checkAuth` token detection |
| `tests/unit/api-interceptor.test.js`|    14 | Long-running endpoints (attacks, scanners, MCP test, campaigns, reports) get 15-min timeout; everything else keeps default 30s |
| **Total**                           | **29** |                                                      |

## How to run

From `minerva/frontend/`:

```bash
# Run all frontend unit tests + HTML report
npm test

# Watch mode (re-runs on file change — useful while developing)
npm run test:watch

# Interactive Vitest UI in the browser (great for live demo)
npm run test:ui
```

## Latest result

```
 Test Files  2 passed (2)
      Tests  29 passed (29)
   Duration  2.61s
```

**Pass rate:** 29 / 29 (100%)
**Wall-clock:** 2.61 seconds
**HTML report:** `frontend/reports/tests/frontend_unit_test_report/index.html`
(open via `npx vite preview --outDir reports/tests/frontend_unit_test_report`)

---

# Combined session result

| Layer    | Tests | Time   | Pass rate |
|----------|------:|-------:|----------:|
| Backend  |    89 | 3.82s  |   100%    |
| Frontend |    29 | 2.61s  |   100%    |
| **Total**|**118**|**6.43s**| **100%** |

---

## What this proves to the marker

1. **Correctness — both layers** — every authentication flow (server
   header composition + client role check), every CVSS-category mapping,
   every validation rule has at least one test pinning its behaviour.
2. **Robustness** — edge cases (empty input, malformed JSON, wrong
   types, mutation safety, network failures during logout) are all
   asserted.
3. **Maintainability** — a future change that breaks any contract will
   fail in CI within ~6 seconds, named down to the exact assertion.
4. **Standards-based stack** — `pytest` + `pytest-html` for Python,
   `vitest` + `@testing-library/react` + `jsdom` for JavaScript. Both
   are the de-facto industry tools for their respective ecosystems.
