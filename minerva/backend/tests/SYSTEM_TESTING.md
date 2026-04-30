# System / End-to-End Testing — Minerva (full stack)

**Session 4 of 10** in the Minerva FYP testing programme.

---

## What is System / E2E Testing?

System / E2E tests drive the **real product** as a real user would —
a real browser (Chromium, controlled by Playwright) loads the real
React frontend, which talks to the real Flask backend, which talks to
the real SQLite database. **Nothing is mocked.**

Where unit tests verify functions, component tests verify rendered
DOM, and integration tests verify the API + DB layer, system tests
verify *the whole product* end-to-end. A passing E2E test is the
strongest evidence that a feature actually works for users.

```
┌────────────────────────────────────────┐
│  Playwright (Chromium browser)         │
│      ↓ navigates, clicks, types        │
│  React frontend  (Vite :3000)          │
│      ↓ fetch /api/v1/...               │
│  Flask backend   (run.py :5000)        │
│      ↓ SQLAlchemy                      │
│  SQLite DB       (instance/aegis_dev)  │
└────────────────────────────────────────┘
```

---

## Scope of this session

| User journey                    | What it proves                                                                |
|---------------------------------|-------------------------------------------------------------------------------|
| Login form renders on `/login`  | The auth route is wired and the form is reachable                             |
| Unauthenticated users redirected| `ProtectedRoute` actually protects routes — visiting `/dashboard` bounces back |
| Bad credentials rejected (401)  | The full chain (form → axios → Flask → bcrypt → 401 → store.error) works     |
| Successful login → `/dashboard` | The happy path works: form fill → API → token mint → routing → dashboard renders |
| Session persists on reload      | Zustand `persist` keeps the user logged in across page reloads                |
| Authenticated navigation works  | Targets, Attacks, Reports, Scanners, Settings pages all reachable post-login  |
| Unknown routes redirect         | The catch-all redirects to `/dashboard` for authenticated users               |

---

## Test inventory (11 tests)

| File                                       | Tests | What it proves                                                       |
|--------------------------------------------|------:|----------------------------------------------------------------------|
| `frontend/tests/e2e/login.spec.js`         |     5 | Login form, redirect-when-unauthed, bad-creds rejection, happy login, session persistence |
| `frontend/tests/e2e/navigation.spec.js`    |     6 | Authenticated nav to Targets, Attacks, Reports, Scanners, Settings + 404 handling |
| **Total**                                  | **11**|                                                                      |

---

## Prerequisites — start two servers before running

E2E tests run against the **live** stack, so both must be up first.

```bash
# Terminal 1 — backend (Flask) on :5000
cd minerva/backend
PYTHONIOENCODING=utf-8 python run.py

# Terminal 2 — frontend (Vite) on :3000
cd minerva/frontend
npm run dev
```

Verify both are up:
```bash
curl http://localhost:5000/api/v1/health/ready   # → {"status":"ready",...}
curl http://localhost:3000/                       # → 200 OK
```

---

## How to run

```bash
# Run E2E tests
cd minerva/frontend
npm run test:e2e

# Open the HTML report afterwards
npm run test:e2e:report

# Live UI dashboard (best for demoing — pause/step through each test)
npm run test:e2e:ui

# Override credentials if your install uses different ones
E2E_ADMIN_EMAIL=admin@minerva.local E2E_ADMIN_PASSWORD=admin123 npm run test:e2e
```

---

## Latest result

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

**Pass rate:** 11 / 11 (100 %)
**Wall-clock:** ~35 s (real browser + real network round-trips, hence slower)
**HTML report:** `frontend/reports/tests/frontend_e2e_test_report/index.html`
**Trace files:** auto-captured on failure (visual replay of every action)

---

## Why this is the strongest test layer

Each E2E test exercises code paths that no other layer can reach:
- **Browser-specific behaviour** — actual browser HTTP requests with cookies,
  CORS, localStorage persistence, real DOM rendering by React.
- **The full integration of every layer** — front-end routing + auth store
  + axios interceptors + Flask routing + JWT decoding + SQLAlchemy + SQLite
  all have to cooperate for a single test to pass.
- **Visual regression evidence** — Playwright captures screenshots, video,
  and a trace zip on failure. The trace can be replayed in a browser like
  a video, with every DOM mutation, network request and console log shown.

A green E2E run means "a real user can actually log in and use the app
right now."

---

## What this proves to the marker

1. **The product works end-to-end** — not just unit-by-unit, but as a
   coherent application from the user's first click to a working dashboard.
2. **Authentication and authorisation hold** — protected routes redirect,
   bad credentials are rejected at the API layer, sessions persist
   across reloads.
3. **Routing is wired** — every advertised page is reachable after login.
4. **Reproducible evidence** — the HTML report and trace viewer let
   anyone (your professor included) replay the exact browser session that
   passed.
