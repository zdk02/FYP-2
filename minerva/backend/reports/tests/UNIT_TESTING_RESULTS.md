# Unit Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Session 1 of 10 — Unit Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **118 / 118 tests passed (100%)** — total wall-clock **3.72 s**

---

## 1. What was tested and why

Unit tests verify the smallest individually testable units of the
system — pure functions, single classes, and state stores — in
isolation from databases, networks, and the browser. They are the
foundation layer of the test pyramid.

The Minerva project has two distinct codebases. **Both** were
unit-tested independently using their respective ecosystems' standard
tooling.

| Layer    | Language    | Framework                                | Runner   |
|----------|-------------|------------------------------------------|----------|
| Backend  | Python 3.12 | `pytest` 9.0 + `pytest-html` 4.2          | CLI      |
| Frontend | JavaScript  | `vitest` 4.1 + `@testing-library/react` + `jsdom` | CLI / browser UI |

---

## 2. Backend results — 89 / 89 passed in 1.13 s

```
============================= test session starts =============================
platform win32 -- Python 3.12 -- pytest-9.0.3
collected 89 items

tests/unit/test_attack_helpers.py ........... ............ [ 15%]   PASSED
tests/unit/test_cve_schema_validation.py ........ ........ [ 39%]   PASSED
tests/unit/test_cvss_scoring.py ......... ............... [ 62%]   PASSED
tests/unit/test_evidence_builders.py ........... ........ [ 78%]   PASSED
tests/unit/test_mcp_client_auth.py ......... ........... [100%]   PASSED

============================= 89 passed in 1.13s ==============================
```

| Test file                            | Tests | Module under test                  | What it proves                                        |
|--------------------------------------|------:|------------------------------------|-------------------------------------------------------|
| `test_mcp_client_auth.py`            |    20 | `app/services/mcp_client.py`        | All 5 auth schemes (bearer, api_key, basic, oauth2, custom) build correct headers; bad input is handled gracefully |
| `test_cvss_scoring.py`               |    24 | `app/services/cvss.py`              | Category → CVSS 3.1 mapping; confidence cap; finding dedupe; A-F risk grading boundaries |
| `test_evidence_builders.py`          |    14 | `app/services/evidence.py`          | Findings have stable shape; evidence builders produce uniform dicts; SHA-256 file digests |
| `test_cve_schema_validation.py`      |    16 | `app/services/cve_schema.py`        | Malformed scanner-plugin YAML is rejected with clear, field-level error messages |
| `test_attack_helpers.py`             |    15 | `app/services/attack_helpers.py`    | MCP tool-schema parsing; keyword-based tool selection; default-fill logic |
| **Total**                            | **89** |                                     |                                                       |

**HTML report (open in any browser):**
`backend/reports/tests/unit_test_report.html`

**Reproduce:**
```bash
cd minerva/backend
python -m pytest tests/unit/ -v
```

---

## 3. Frontend results — 29 / 29 passed in 2.59 s

```
 RUN  v4.1.5 C:/Users/Zeinab/Downloads/FYP/minerva/minerva/frontend

 ✓ tests/unit/api-interceptor.test.js (14 tests) 16 ms
 ✓ tests/unit/authStore.test.js     (15 tests) 22 ms

 Test Files  2 passed (2)
      Tests  29 passed (29)
   Duration  2.59 s
```

| Test file                            | Tests | Module under test                  | What it proves                                        |
|--------------------------------------|------:|------------------------------------|-------------------------------------------------------|
| `authStore.test.js`                  |    15 | `src/stores/authStore.js`           | `hasRole`, `isAdmin`, `isManager`; login success / failure / logout state transitions; `updateUser` field merge; `checkAuth` token detection |
| `api-interceptor.test.js`            |    14 | `src/services/api.js`               | Long-running endpoints (attacks, scanners, MCP test, campaigns, reports) get a 15-min timeout; everything else keeps the default 30 s |
| **Total**                            | **29** |                                     |                                                       |

**HTML report (interactive — open via Vite preview):**
```bash
cd minerva/frontend
npx vite preview --outDir reports/tests/frontend_unit_test_report
```

**Reproduce:**
```bash
cd minerva/frontend
npm test
```

**Live demo dashboard (most visually impressive):**
```bash
npm run test:ui
```

---

## 4. Combined totals

| Layer    | Test files | Tests | Wall-clock | Pass rate |
|----------|-----------:|------:|-----------:|----------:|
| Backend  |          5 |    89 |   1.13 s   |    100 %  |
| Frontend |          2 |    29 |   2.59 s   |    100 %  |
| **Total**|        **7**| **118**|**3.72 s**|  **100 %**|

---

## 5. What this proves

1. **Correctness across both languages** — every authentication code
   path (server-side header composition + client-side role check),
   every CVSS-category mapping, every YAML validation rule has at least
   one assertion pinning its behaviour.
2. **Robustness** — edge cases (empty input, malformed JSON, wrong
   types, immutability of inputs, network failure during logout) are
   all asserted, not just the happy path.
3. **Maintainability** — any future change that breaks one of these
   contracts will fail in CI in under 4 seconds, named down to the
   exact assertion.
4. **Standards-based stack** — `pytest` is the de-facto Python testing
   framework; `vitest` + `@testing-library/react` is the de-facto
   modern React testing stack. No bespoke or hand-rolled framework.

---

## 6. File inventory (artefacts to inspect)

**Backend:**
- `minerva/backend/pytest.ini` — pytest config with markers per test type
- `minerva/backend/tests/conftest.py` — shared fixtures
- `minerva/backend/tests/unit/test_mcp_client_auth.py`
- `minerva/backend/tests/unit/test_cvss_scoring.py`
- `minerva/backend/tests/unit/test_evidence_builders.py`
- `minerva/backend/tests/unit/test_cve_schema_validation.py`
- `minerva/backend/tests/unit/test_attack_helpers.py`
- `minerva/backend/reports/tests/unit_test_report.html` ← **HTML report**
- `minerva/backend/reports/tests/backend_unit_terminal_output.txt` ← raw run log

**Frontend:**
- `minerva/frontend/vite.config.js` — vitest config block
- `minerva/frontend/tests/setup.js` — test environment bootstrap
- `minerva/frontend/tests/unit/authStore.test.js`
- `minerva/frontend/tests/unit/api-interceptor.test.js`
- `minerva/frontend/reports/tests/frontend_unit_test_report/index.html` ← **HTML report**
- `minerva/frontend/reports/tests/frontend_unit_terminal_output.txt` ← raw run log

**Documentation:**
- `minerva/backend/tests/UNIT_TESTING.md` — full session writeup

---

*Session 1 of 10 in the Minerva FYP testing programme. Next session: Integration Testing.*
