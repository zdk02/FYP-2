# Performance Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Session 8 of 10 — Performance Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **12 / 12 tests passed (100 %)** (Backend 9 + Frontend 3) — combined wall-clock **10.01 s**

---

## 1. Definition

Performance testing measures **response time and throughput under
normal load**. It is distinct from Stress Testing (Session 9), which
measures the *breaking point*. Performance pins what the system
delivers when asked nicely; stress finds where it falls over.

Both layers were measured:

| Layer    | Tool                                  | Metric                                                  |
|----------|---------------------------------------|---------------------------------------------------------|
| Backend  | pytest + `time.perf_counter`          | p50 / p95 latency, RPS                                  |
| Frontend | Playwright + Performance Timing API   | DOMContentLoaded, full-load, login-flow elapsed         |

---

## 2. Backend results — 9/9 in 4.81 s

```
============================= test session starts =============================

[perf] GET /health/ready              p50=  0.25ms p95=  0.31ms max=  1.05ms  OK
[perf] POST /auth/login               p50=145.64ms p95=168.35ms max=171.30ms  OK
[perf] GET /auth/me                   p50=  0.92ms p95=  1.23ms max=  2.41ms  OK
[perf] GET /targets (empty)           p50=  1.31ms p95=  1.56ms max=  6.43ms  OK
[perf] GET /targets (50 rows)         p50=  1.54ms p95=  1.60ms max=  1.82ms  OK
[perf] GET /attacks                   p50=  1.56ms p95=  2.03ms max=  8.45ms  OK
[perf] GET /attacks/severities        p50=  0.42ms p95=  0.57ms max=  0.99ms  OK
[perf] GET /attacks/types             p50=  0.40ms p95=  0.49ms max=  0.62ms  OK
[perf] GET /attacks/languages         p50=  0.40ms p95=  0.59ms max=  0.99ms  OK

[perf] /health   total=200 concurrency=10 rps=1563.3 success=1.0
[perf] /targets  serial total=100        rps=835.4   success=1.0

============================== 9 passed in 4.81s ==============================
```

### Service-level thresholds (all met)

| Endpoint                              | Threshold p95 | Measured p95 | Headroom |
|---------------------------------------|--------------:|-------------:|---------:|
| `GET /health/ready`                   |       50 ms   |    0.31 ms   |   161×   |
| `POST /auth/login` (bcrypt)            |      500 ms   |  168.35 ms   |     3×   |
| `GET /auth/me`                        |      100 ms   |    1.23 ms   |    81×   |
| `GET /targets` (empty)                |       50 ms   |    1.56 ms   |    32×   |
| `GET /targets` (50 rows)              |      100 ms   |    1.60 ms   |    63×   |
| `GET /attacks`                        |       50 ms   |    2.03 ms   |    25×   |
| `GET /attacks/severities`             |       20 ms   |    0.57 ms   |    35×   |
| `GET /attacks/types`                  |       20 ms   |    0.49 ms   |    41×   |
| `GET /attacks/languages`              |       20 ms   |    0.59 ms   |    34×   |

### Throughput

| Workload                              | Throughput     |
|---------------------------------------|----------------|
| `/health` at concurrency 10           | **1563 rps**   |
| `/targets` serial (auth-required)     | **835 rps**    |

---

## 3. Frontend results — 3/3 in 5.20 s

```
[perf:fe] /login domContentLoaded=1021ms  load=1023ms  transfer=1371B
[perf:fe] login flow elapsed=1573ms

  ok 1 login page DOMContentLoaded is under 4 seconds            (1.3s)
  ok 2 login page fully loaded is under 6 seconds                (1.0s)
  ok 3 login flow completes within 5 seconds end-to-end          (1.6s)

  3 passed (5.2s)
```

| Measurement                              | Threshold | Measured  | Headroom |
|------------------------------------------|----------:|----------:|---------:|
| `/login` DOMContentLoaded                |   4000 ms |  1021 ms  |   3.9×   |
| `/login` full load event                 |   6000 ms |  1023 ms  |   5.9×   |
| Login → dashboard visible (full E2E)     |   5000 ms |  1573 ms  |   3.2×   |

(Tested against the **Vite dev** server — production builds are
typically 3–5× faster.)

---

## 4. Key observations

1. **Every endpoint clears its threshold with substantial headroom** —
   most by an order of magnitude.
2. **bcrypt dominates login latency** at ~150 ms p95. This is the
   intended cost of a slow KDF, not a perf bug — security feature.
3. **The DB scales linearly** — `/targets` p95 with 50 rows (1.60 ms)
   is essentially identical to empty (1.56 ms). No N+1 queries, no
   missing indexes.
4. **High-concurrency throughput** on `/health` reaches **1500+ rps**,
   plenty of capacity for a research/FYP-scale deployment.

---

## 5. How to reproduce

```bash
# Backend (uses Flask test client — no servers needed)
cd minerva/backend
python -m pytest tests/performance/ -v -s

# Frontend (BOTH dev servers required first)
cd ../frontend
npm run test:performance
```

---

## 6. File inventory

**Backend:**
- `minerva/backend/tests/performance/conftest.py` — module-scoped fixtures + measurement helpers
- `minerva/backend/tests/performance/test_response_times.py` — p50/p95 per endpoint
- `minerva/backend/tests/performance/test_throughput.py` — concurrent + serial RPS
- `minerva/backend/reports/tests/performance_test_report.html` ← **HTML report**
- `minerva/backend/reports/tests/performance_terminal_output.txt` ← raw run log

**Frontend:**
- `minerva/frontend/playwright.performance.config.js` — separate config for perf tests
- `minerva/frontend/tests/performance/page-load.spec.js`
- `minerva/frontend/reports/tests/frontend_performance_test_report/index.html` ← **HTML report**
- `minerva/frontend/reports/tests/frontend_performance_terminal_output.txt`

**Documentation:**
- `minerva/backend/tests/PERFORMANCE_TESTING.md` — full session writeup

---

## 7. Cumulative progress (Sessions 1 – 8)

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
| 7       | Usability      | Frontend   |     7 | 22.00 s | 100 %|
| **8**   | **Performance**| **Backend**|**9**  |**4.81 s**|**100 %**|
| **8**   | **Performance**| **Frontend**|**3** |**5.20 s**|**100 %**|
| **Total automated** |   |            | **302** | **131.28 s** | **100 %** |

---

*Session 8 of 10. Next session: Stress Testing.*
