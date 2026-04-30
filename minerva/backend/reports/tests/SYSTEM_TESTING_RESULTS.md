# System / End-to-End Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Session 4 of 10 — System / End-to-End Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **11 / 11 tests passed (100 %)** — wall-clock **35.2 s**

---

## 1. What this session demonstrates

A real Chromium browser, controlled by **Playwright**, drives the real
React frontend (Vite on :3000) which talks to the real Flask backend
(:5000) which writes to the real SQLite database.  Nothing is mocked.

```
Playwright Chromium  →  React/Vite (:3000)  →  Flask (:5000)  →  SQLite
```

This is the **strongest** evidence layer in the testing programme:
each test exercises every layer of the stack at once, in the same
configuration a real user would.

---

## 2. Result

```
Running 11 tests using 1 worker

  ok  1 [chromium] login.spec.js     › shows the sign-in form on /login              (2.6s)
  ok  2 [chromium] login.spec.js     › redirects unauthenticated visits to /login    (3.5s)
  ok  3 [chromium] login.spec.js     › rejects invalid credentials and stays         (2.9s)
  ok  4 [chromium] login.spec.js     › logs in with admin credentials                (2.3s)
  ok  5 [chromium] login.spec.js     › persists session across a page reload         (3.0s)
  ok  6 [chromium] navigation.spec.js › navigates from dashboard to Targets page      (2.9s)
  ok  7 [chromium] navigation.spec.js › navigates to Attacks page                     (2.5s)
  ok  8 [chromium] navigation.spec.js › navigates to Reports page                     (2.8s)
  ok  9 [chromium] navigation.spec.js › navigates to Scanners page                    (3.5s)
  ok 10 [chromium] navigation.spec.js › navigates to Settings page                    (3.5s)
  ok 11 [chromium] navigation.spec.js › unknown route redirects to dashboard          (3.3s)

  11 passed (35.2s)
```

---

## 3. Test inventory

| Test file                                      | Tests | User journey exercised                                                |
|------------------------------------------------|------:|-----------------------------------------------------------------------|
| `frontend/tests/e2e/login.spec.js`             |     5 | Login form, route protection, bad-creds rejection, happy-path login, session persistence |
| `frontend/tests/e2e/navigation.spec.js`        |     6 | Authenticated navigation to Targets, Attacks, Reports, Scanners, Settings + unknown-route redirect |
| **Total**                                      | **11**|                                                                       |

### Key contracts pinned by these tests

| Contract                                                                       | Test that proves it                                                              |
|--------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| Visiting `/dashboard` while logged out redirects to `/login`                   | `redirects unauthenticated visits to /login`                                     |
| The backend rejects bad credentials with HTTP 401 and the UI doesn't proceed   | `rejects invalid credentials and stays on /login`                                |
| Successful login renders the Dashboard heading and the welcome line            | `logs in with admin credentials and lands on the dashboard`                      |
| Persisted Zustand store keeps the user logged in across reloads                | `persists session across a page reload`                                          |
| Every advertised section (Targets, Attacks, Reports, Scanners, Settings) loads | 5 tests in `navigation.spec.js`                                                  |
| Unknown routes fall back to `/dashboard` for authenticated users               | `unknown route redirects to dashboard`                                           |

---

## 4. How to reproduce

**Prerequisites — start both servers first** (in separate terminals):

```bash
# Terminal 1 — Flask backend on :5000
cd minerva/backend
PYTHONIOENCODING=utf-8 python run.py

# Terminal 2 — Vite frontend on :3000
cd minerva/frontend
npm run dev
```

**Run the E2E suite:**

```bash
cd minerva/frontend
npm run test:e2e               # → 11 passed in ~35s

# Then view the HTML report
npm run test:e2e:report

# Or run with the live UI dashboard (best for live demo)
npm run test:e2e:ui
```

---

## 5. File inventory (artefacts to inspect)

- `minerva/frontend/playwright.config.js` — Playwright config (chromium, HTML reporter, traces, screenshots, videos)
- `minerva/frontend/tests/e2e/login.spec.js`
- `minerva/frontend/tests/e2e/navigation.spec.js`
- `minerva/frontend/reports/tests/frontend_e2e_test_report/index.html` ← **HTML report**
- `minerva/frontend/reports/tests/e2e_terminal_output.txt` ← raw run log
- `minerva/frontend/test-results/` ← per-test traces, videos, screenshots (auto-captured on failure)
- `minerva/backend/tests/SYSTEM_TESTING.md` — full session writeup

### Bonus artefacts (Playwright-specific)

Playwright produces evidence beyond a HTML pass/fail:

- **Trace files (`trace.zip`)** — replay every step of a test in a
  browser-like UI with DOM snapshots, network logs, and console output.
- **Videos (`.webm`)** — the actual recording of the browser
  performing the test.
- **Screenshots** — captured automatically on failure.

These all live under `frontend/test-results/` after a run.

---

## 6. Cumulative progress (Sessions 1 – 4)

| Session | Type           | Layer    | Tests | Time    | Pass |
|--------:|----------------|----------|------:|--------:|-----:|
| 1       | Unit           | Backend  |    89 |  1.13 s | 100 %|
| 1       | Unit           | Frontend |    29 |  2.59 s | 100 %|
| 2       | Integration    | Backend  |    43 | 18.96 s | 100 %|
| 3       | Component      | Frontend |    26 |  2.44 s | 100 %|
| 4       | System / E2E   | Full stack |  11 | 35.20 s | 100 %|
| **Total** |              |          | **198** | **60.32 s** | **100 %** |

---

*Session 4 of 10 in the Minerva FYP testing programme. Next session: Acceptance Testing.*
