# Component Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Session 3 of 10 — Component Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **26 / 26 tests passed (100 %)** — wall-clock **2.44 s**

---

## 1. What component testing means here

A component test renders a single React component into a fake browser
(`jsdom`) and asserts on the actual DOM produced. Where unit tests
verified pure functions in isolation, component tests verify what the
end user actually sees and what happens when they click or type.

```
React component
   ↓ rendered into jsdom by @testing-library/react
DOM tree
   ↓ queried by role / text / display-value
Assertions on visible content
   ↓ user interaction simulated by fireEvent
DOM changes verified again
```

External dependencies (axios, the real backend, React Query) are not
exercised here — that's the job of the eventual System/E2E session.
This isolation is what makes component tests fast (<500 ms each) and
what makes their failures pinpoint exactly which prop or interaction
broke.

---

## 2. Result

```
 RUN  v4.1.5 C:/Users/Zeinab/Downloads/FYP/minerva/minerva/frontend

 ✓ tests/component/CheckBuilder.test.jsx  (10 tests)  313 ms
 ✓ tests/component/FindingsTable.test.jsx (16 tests)  361 ms

 Test Files  2 passed (2)
      Tests  26 passed (26)
   Duration  2.44 s
```

---

## 3. Test inventory

| Test file                                            | Tests | Component                                       | Behaviour pinned                                                   |
|------------------------------------------------------|------:|-------------------------------------------------|--------------------------------------------------------------------|
| `tests/component/FindingsTable.test.jsx`             |    16 | `src/components/scanners/FindingsTable.jsx`     | Empty / populated / fallback rendering + expand-collapse toggle    |
| `tests/component/CheckBuilder.test.jsx`              |    10 | `src/components/scanners/CheckBuilder.jsx`      | Add / remove / edit / type-switch — full controlled-form contract  |
| **Total**                                            | **26**|                                                 |                                                                    |

### Key contracts pinned by these tests

| Contract                                                                         | Test that proves it                                                          |
|----------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| Empty findings list shows a "No findings." placeholder, not a broken table       | `renders the "No findings." placeholder when given no findings`              |
| Each finding produces exactly one visible row                                    | `renders one row per finding`                                                |
| CVE column links out to NVD only when the id is in CVE-YYYY-NNNN format          | `renders a CVE link to NVD when the CVE id starts with "CVE-"`               |
| Missing severity falls back to "info", missing confidence falls back to "low"    | `falls back to "info" severity when severity is missing`                     |
| Capitalised severity values are lowercased before display                        | `lowercases severity values that came in capitalised`                        |
| Clicking the chevron toggles description visibility (open ↔ closed)              | `hides the description again on a second click (toggle)`                     |
| "Add check" appends to existing checks rather than replacing them                 | `appends to existing checks rather than replacing them`                      |
| Selecting a check type seeds required-with-default fields from the schema        | `switching to port_open seeds host with the schema default 127.0.0.1`        |
| Removing a row produces a new array with that row filtered out                   | `calls onChange with the row removed`                                        |
| Editing a field fires `onChange` with the updated row, not the old one            | `typing into the path input fires onChange with the updated row`             |

---

## 4. How to reproduce

From `minerva/frontend/`:

```bash
# Component-only run + HTML report
npm run test:component

# Or interactive UI dashboard (best for live demo)
npm run test:ui
```

Expected output: `26 passed in ~2.5 s`.

---

## 5. File inventory (artefacts to inspect)

- `minerva/frontend/tests/component/FindingsTable.test.jsx`
- `minerva/frontend/tests/component/CheckBuilder.test.jsx`
- `minerva/frontend/reports/tests/frontend_component_test_report/index.html` ← **HTML report**
- `minerva/frontend/reports/tests/component_terminal_output.txt` ← raw run log
- `minerva/backend/tests/COMPONENT_TESTING.md` — full session writeup
- `minerva/frontend/package.json` — `test:component` and `test:unit` scripts

---

## 6. Cumulative progress (Sessions 1 – 3)

| Session | Type        | Layer    | Tests | Time    | Pass |
|--------:|-------------|----------|------:|--------:|-----:|
| 1       | Unit        | Backend  |    89 |  1.13 s | 100 %|
| 1       | Unit        | Frontend |    29 |  2.59 s | 100 %|
| 2       | Integration | Backend  |    43 | 18.96 s | 100 %|
| 3       | Component   | Frontend |    26 |  2.44 s | 100 %|
| **Total** |           |          | **187** | **25.12 s** | **100 %** |

---

*Session 3 of 10 in the Minerva FYP testing programme. Next session: System / End-to-End Testing.*
