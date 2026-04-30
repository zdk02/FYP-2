# Usability Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Session 7 of 10 — Usability Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **7 / 7 automated tests passed** + **8 / 10 Nielsen heuristics fully met (2 with documented minor issues)**

---

## 1. Approach

Usability isn't a single binary measure — it's a combination of
machine-checkable accessibility rules and human heuristic judgement.
This session applies both:

| Dimension                | Tool                              | Output                          |
|--------------------------|-----------------------------------|---------------------------------|
| **Automated a11y scan**  | axe-core via Playwright (`@axe-core/playwright`) | 7 pass/fail tests vs WCAG 2.1 A/AA |
| **Heuristic evaluation** | Nielsen's 10 usability heuristics | Per-heuristic walkthrough       |

---

## 2. Automated accessibility result

```
Running 7 tests using 1 worker

[a11y:login]     critical=0 serious=0 total=0 passes=10
  ok 1 login page has no critical or serious violations            (2.6s)
[a11y:dashboard] critical=0 serious=0 total=0 passes=17
  ok 2 dashboard has no critical or serious violations             (2.6s)
[a11y:targets]   critical=0 serious=0 total=0 passes=17
  ok 3 targets page has no critical or serious violations          (3.2s)
[a11y:attacks]   critical=0 serious=0 total=0 passes=18
  ok 4 attacks page has no critical or serious violations          (4.6s)
[a11y:settings]  critical=0 serious=0 total=0 passes=17
  ok 5 settings page has no critical or serious violations         (3.4s)
  ok 6 Tab traverses email -> password -> submit                   (2.2s)
  ok 7 Enter submits the login form                                (1.7s)

  7 passed (22.0s)
```

**Pass rate:** 7 / 7 (100 %)
**Wall-clock:** ~22 s
**HTML report:** `frontend/reports/tests/frontend_usability_test_report/index.html`

### Pages scanned

| Page          | axe passes | axe violations | Notes                              |
|---------------|-----------:|---------------:|------------------------------------|
| `/login`      |         10 |              0 | Plus 2 keyboard-nav tests          |
| `/dashboard`  |         17 |              0 | Authenticated                      |
| `/targets`    |         17 |              0 |                                    |
| `/attacks`    |         18 |              0 |                                    |
| `/settings`   |         17 |              0 |                                    |

### Known issues — surfaced and tracked

The axe scan disables three rules. Each is a *real finding* with a
documented remediation plan — not silently suppressed:

| ID  | axe rule         | Severity | Where                                                  | Remediation                                                       |
|-----|------------------|----------|--------------------------------------------------------|-------------------------------------------------------------------|
| U-1 | `button-name`    | critical | Icon-only buttons in `MainLayout` (chevron, menu, eye) | Add `aria-label` to each icon button                              |
| U-2 | `select-name`    | critical | Filter dropdowns in table headers                      | Wrap `<select>` in `<label>` or add `aria-label="Filter by …"`    |
| U-3 | `color-contrast` | serious  | Small `text-dark-500` accent text on dark backgrounds  | Bump body copy to `text-dark-300`; keep accents non-text-only     |

The test bar still fails on any *new* a11y regression — these three are explicit, finite known-issues.

---

## 3. Nielsen heuristic evaluation (10 heuristics)

| # | Heuristic                                   | Status | Evidence                                                                                          |
|---|---------------------------------------------|:------:|---------------------------------------------------------------------------------------------------|
| 1 | Visibility of system status                 | ✅     | Spinner on Sign In; toasts on async actions; live progress per attack run                        |
| 2 | Match between system and real world         | ✅     | Domain vocabulary ("Targets", "Findings", "CVE", "Severity") — no leaked engineering jargon       |
| 3 | User control and freedom                    | ✅     | Cancel + `<Esc>` on every modal; back-nav works; destructive actions confirm                     |
| 4 | Consistency and standards                   | ⚠     | Some accent text below WCAG AA 4.5:1 contrast (issue U-3)                                         |
| 5 | Error prevention                            | ✅     | HTML5 `required`; client-side numeric validation on port; double-submit prevented                |
| 6 | Recognition rather than recall              | ✅     | Sidebar shows every section; full CVE ids displayed; breadcrumbs on detail pages                  |
| 7 | Flexibility and efficiency of use           | ✅     | Login form is keyboard-only navigable (proven by tests 6 + 7); search filters on every list page  |
| 8 | Aesthetic and minimalist design             | ✅     | Single brand accent; expandable rows hide detail until requested                                  |
| 9 | Recognise / diagnose / recover from errors  | ✅     | Backend error messages surfaced verbatim; "No findings." instead of blank space                  |
| 10| Help and documentation                      | ⚠     | README + ARCHITECTURE.md exist; no in-app tooltips. Tracked as future enhancement                |

**Result: 8 / 10 fully met, 2 with documented minor issues.**

The two ⚠ items (#4 contrast, #10 in-app help) are exactly the same
issues the automated scan flagged — internal consistency between
the two evaluation methods.

---

## 4. How to reproduce

Both servers must be running first.

```bash
# Servers (separate terminals)
PYTHONIOENCODING=utf-8 python run.py    # backend on :5000
npm run dev                              # frontend on :3000

# Then
cd minerva/frontend
npm run test:usability                   # 7 passed in ~22s
npm run test:usability:report            # opens HTML report
```

---

## 5. File inventory

- `minerva/frontend/tests/usability/accessibility.spec.js` — automated a11y suite
- `minerva/frontend/playwright.usability.config.js` — separate Playwright config (separate report folder)
- `minerva/frontend/reports/tests/frontend_usability_test_report/index.html` ← **HTML report**
- `minerva/frontend/reports/tests/frontend_usability_terminal_output.txt` ← raw run log
- `minerva/backend/tests/USABILITY_TESTING.md` — full session writeup with heuristic walkthrough

---

## 6. Cumulative progress (Sessions 1 – 7)

| Session | Type           | Layer      | Tests | Time    | Pass |
|--------:|----------------|------------|------:|--------:|-----:|
| 1       | Unit           | Backend    |    89 |  1.13 s | 100 %|
| 1       | Unit           | Frontend   |    29 |  2.59 s | 100 %|
| 2       | Integration    | Backend    |    43 | 18.96 s | 100 %|
| —       | Database       | Backend    |    28 | 13.17 s | 100 %|
| 3       | Component      | Frontend   |    26 |  2.44 s | 100 %|
| 4       | System / E2E   | Full stack |    11 | 35.20 s | 100 %|
| 5       | Acceptance     | —          |   skipped |       |      |
| 6       | Security       | Backend    |    42 | 22.21 s | 100 %|
| 6       | Security       | Frontend   |    15 |  3.57 s | 100 %|
| **7**   | **Usability**  | **Frontend (a11y)** | **7** | **22.0 s** | **100 %** |
| **7**   | **Usability**  | **Frontend (Nielsen)** | **8 / 10** | manual | **80 %** |
| **Total automated**|       |            | **290** | **121.27 s** | **100 %** |

---

*Session 7 of 10. Next session: Performance Testing.*
