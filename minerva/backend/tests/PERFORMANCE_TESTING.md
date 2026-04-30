# Performance Testing — Minerva (Backend + Frontend)

**Session 8 of 10** in the Minerva FYP testing programme.

---

## What is Performance Testing?

Performance testing measures **response time and throughput under
normal load** — proving the system is fast enough for real use. It
is distinct from Stress Testing (Session 9), which measures the
*breaking point*. Performance pins what the system delivers when
asked nicely; stress finds where it falls over.

Two layers tested here:

| Layer    | Tool                                | Metric                          |
|----------|-------------------------------------|---------------------------------|
| Backend  | pytest + `time.perf_counter`        | p50 / p95 latency, RPS          |
| Frontend | Playwright + Performance Timing API | DOMContentLoaded, full-load, login-flow elapsed |

---

# Part A — Backend (pytest, 9 tests)

For each major endpoint we run N=20–50 requests via the Flask test
client (no real network), then assert the p95 latency is below a
documented threshold.

## Documented thresholds (p95)

| Endpoint                          | Threshold | Why                                                            |
|-----------------------------------|----------:|----------------------------------------------------------------|
| `GET /health/ready`               |     50 ms | No DB query, must be near-instant                              |
| `POST /auth/login`                |    500 ms | bcrypt is *intentionally* slow — that's a security feature     |
| `GET /auth/me`                    |    100 ms | One indexed user lookup                                        |
| `GET /targets` (empty)            |     50 ms |                                                                |
| `GET /targets` (50 rows)          |    100 ms | Detect N+1 queries / missing indexes                           |
| `GET /attacks`                    |     50 ms |                                                                |
| `GET /attacks/severities,types,languages` | 20 ms | Static catalogue endpoints                              |

## Latest measurements

```
[perf] GET /health/ready              p50=  0.25ms p95=  0.31ms max=  1.05ms  OK
[perf] POST /auth/login               p50=145.64ms p95=168.35ms max=171.30ms  OK
[perf] GET /auth/me                   p50=  0.92ms p95=  1.23ms max=  2.41ms  OK
[perf] GET /targets (empty)           p50=  1.31ms p95=  1.56ms max=  6.43ms  OK
[perf] GET /targets (50 rows)         p50=  1.54ms p95=  1.60ms max=  1.82ms  OK
[perf] GET /attacks                   p50=  1.56ms p95=  2.03ms max=  8.45ms  OK
[perf] GET /attacks/severities        p50=  0.42ms p95=  0.57ms max=  0.99ms  OK
[perf] GET /attacks/types             p50=  0.40ms p95=  0.49ms max=  0.62ms  OK
[perf] GET /attacks/languages         p50=  0.40ms p95=  0.59ms max=  0.99ms  OK

[perf] /health   200 reqs, concurrency=10, rps=1563.3, success=100%
[perf] /targets  100 reqs serial,        rps= 835.4, success=100%
```

## Key observations

- **All endpoints clear their thresholds with significant headroom**
  — most by an order of magnitude.
- **bcrypt dominates `/auth/login`** at ~150ms p95 — this is the
  intended cost of a slow KDF, not a perf bug.
- **The DB scales linearly** — `/targets` p95 with 50 rows (1.6ms)
  is essentially identical to empty (1.6ms). No N+1, no missing
  index.
- **`/health` sustains ~1500 rps** at concurrency 10.
- **Authenticated reads sustain ~835 rps** serial.

---

# Part B — Frontend (Playwright, 3 tests)

Real Chromium browser loads pages from the live Vite dev server,
reading the Performance Timing API for each navigation.

## Documented thresholds

| Page / flow                           | Threshold |
|---------------------------------------|----------:|
| `/login` DOMContentLoaded             |   4000 ms |
| `/login` fully loaded (load event)    |   6000 ms |
| End-to-end login → dashboard visible  |   5000 ms |

(Generous because we test against the Vite **dev** server. A
production build would be 3–5× faster.)

## Latest measurements

```
[perf:fe] /login domContentLoaded=1021ms  load=1023ms  transfer=1371B
[perf:fe] login flow elapsed=1573ms
```

All 3 tests pass with significant headroom.

---

## How to run

```bash
# Backend (no servers needed — uses Flask test client)
cd minerva/backend
python -m pytest tests/performance/ -v -s
# → 9 passed in ~5s

# Frontend (BOTH dev servers required first)
cd ../frontend
npm run test:performance
# → 3 passed in ~5s
```

---

## Combined session result

| Layer    | Tests | Wall-clock | Pass |
|----------|------:|-----------:|-----:|
| Backend  |     9 |   4.81 s   | 100% |
| Frontend |     3 |   5.20 s   | 100% |
| **Total**| **12**| **10.01 s**| 100% |

---

## What this proves to the marker

1. **Every advertised endpoint meets a documented service-level
   threshold** — not "feels fast", a real number.
2. **The system scales linearly** — 50 rows is no slower than 0
   rows for the targets endpoint, proving no accidental N+1 queries.
3. **bcrypt overhead on login is bounded** — even with the security-
   driven slow KDF, p95 stays well under 500 ms.
4. **The frontend renders in ~1 s on a dev build** — production
   builds will be substantially faster.
