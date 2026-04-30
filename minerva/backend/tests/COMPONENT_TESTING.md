# Component Testing — Minerva Frontend

**Session 3 of 10** in the Minerva FYP testing programme.

---

## What is Component Testing?

Component testing renders a single React component into a fake browser
environment (`jsdom`), feeds it props, simulates user interactions
(clicks, typing, form submission), and asserts on the resulting DOM.

It sits between unit testing and system/E2E testing:

| Layer            | What it tests                                   | Speed     |
|------------------|-------------------------------------------------|-----------|
| Unit             | Pure functions / stores in isolation            | < 50 ms   |
| **Component**    | **One React component + its rendered DOM**      | < 500 ms  |
| Integration (BE) | API + DB through Flask test client              | ~ 0.5 s   |
| System / E2E     | Real browser driving real frontend + backend    | several s |

Component tests do *not* hit a real backend — `axios` calls and React
Query are not exercised here. That's deliberate: a component test is
about whether the component renders and reacts correctly, given inputs.

---

## Scope of this session

We picked two components from `src/components/scanners/` that have
non-trivial rendering and interaction logic, with no tight coupling to
external infrastructure (no router, no react-query, no recharts).

| Component         | Why it's a good component-test target                        |
|-------------------|--------------------------------------------------------------|
| `FindingsTable`   | Empty / populated branches, severity & confidence labels, NVD-link generation, expand/collapse interaction |
| `CheckBuilder`    | Controlled form: add / remove / edit / type-switch all fire `onChange` with the next state — pin the contract |

---

## Test inventory (26 tests)

| File                                                  | Tests | What it proves                                                |
|-------------------------------------------------------|------:|---------------------------------------------------------------|
| `frontend/tests/component/FindingsTable.test.jsx`     |    16 | Empty placeholder; one row per finding; severity, confidence and CVE columns; NVD link only for `CVE-…` ids; missing-field fallbacks; expand/collapse toggle |
| `frontend/tests/component/CheckBuilder.test.jsx`      |    10 | Empty placeholder; "Add check" appends; type selection seeds required-with-default fields; row removal; field editing — all via `onChange` contract |
| **Total**                                             | **26**|                                                               |

---

## How to run

From `minerva/frontend/`:

```bash
# Run only the component tests + dedicated HTML report
npm run test:component

# All frontend tests (unit + component)
npm test

# Watch mode while developing
npm run test:watch -- tests/component

# Interactive Vitest UI in the browser
npm run test:ui
```

---

## Latest result

```
 ✓ tests/component/CheckBuilder.test.jsx  (10 tests) 313 ms
 ✓ tests/component/FindingsTable.test.jsx (16 tests) 361 ms

 Test Files  2 passed (2)
      Tests  26 passed (26)
   Duration  2.44 s
```

**Pass rate:** 26 / 26 (100 %)
**Wall-clock:** 2.44 s
**HTML report:** `frontend/reports/tests/frontend_component_test_report/index.html`
(open with `npx vite preview --outDir reports/tests/frontend_component_test_report`)

---

## Why these tests catch real bugs

- **`renders a CVE link to NVD when the CVE id starts with "CVE-"`**
  proves the URL-generation logic: a malformed CVE id (e.g. `XSA-…`
  from Xen) won't accidentally produce a broken NVD link.
- **`hides the description again on a second click (toggle)`** proves
  the `expanded` state is actually a toggle and not a one-way switch
  — a regression that's invisible to type checkers and unit tests.
- **`switching to port_open seeds host with the schema default`**
  proves the type-selection branch in `CheckBuilder` correctly walks
  the schema and only seeds defaults for *required* fields — exactly
  matching what the backend `cve_schema` validator expects.
- **`appends to existing checks rather than replacing them`** proves
  the immutable-update contract that the parent page relies on.

---

## What this proves to the marker

1. **The UI matches its props contract** — what the user sees is
   driven by data, in a predictable, testable way.
2. **Interactive behaviour is verified** — clicks, form edits, and
   toggles all produce the documented next state.
3. **Edge cases are pinned** — missing severity, missing CVE, empty
   list, second-click collapse — all asserted, not just the happy path.
4. **No false confidence** — every test renders a real component into
   a real DOM and asserts on what is actually there. We do not stub
   out the component under test.
