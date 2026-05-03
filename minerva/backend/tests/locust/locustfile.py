"""
Minerva — Locust load test.

Industry-standard HTTP load testing against a *running* Flask server
(127.0.0.1:5000). Complements the in-memory pytest perf tests by
exercising the real WSGI stack, real network, and real concurrency.

NOTE: always use ``127.0.0.1`` as the host, NOT ``localhost``. On
Windows ``localhost`` resolves to both ``::1`` (IPv6) and ``127.0.0.1``
(IPv4); when Flask only binds IPv4, the IPv6 connect attempt times
out at ~2 s before falling back, ruining the latency measurements.

Two user classes are defined:

  * AdminBrowsingUser   — simulates an authenticated operator clicking
                          around the dashboard (read-heavy workload).
  * AnonymousVisitor    — hits public endpoints (health) without auth,
                          modelling occasional probe traffic.

Run scenarios:

  # Headless smoke run (10 users, 1 minute) → HTML + CSV reports
  python -m locust -f tests/locust/locustfile.py \\
    --host http://127.0.0.1:5000 --headless \\
    -u 10 -r 2 -t 1m \\
    --html reports/locust/smoke.html --csv reports/locust/smoke

  # Sustained run (50 users, 3 minutes)
  python -m locust -f tests/locust/locustfile.py \\
    --host http://127.0.0.1:5000 --headless \\
    -u 50 -r 5 -t 3m \\
    --html reports/locust/sustained.html --csv reports/locust/sustained

  # Interactive web UI at http://localhost:8089
  python -m locust -f tests/locust/locustfile.py --host http://127.0.0.1:5000
"""

from __future__ import annotations

from locust import HttpUser, task, between, events


# ---------------------------------------------------------------------------
# Default credentials shipped with the FYP demo seed.
# ---------------------------------------------------------------------------

ADMIN_EMAIL = 'admin@minerva.local'
ADMIN_PASSWORD = 'admin123'


# ---------------------------------------------------------------------------
# Authenticated browsing — the realistic workload.
# ---------------------------------------------------------------------------

class AdminBrowsingUser(HttpUser):
    """Authenticated operator clicking around the dashboard.

    Tasks are weighted to match a typical session: lots of list views,
    occasional reads of catalogue endpoints. No writes — load tests
    must be idempotent so they can be re-run safely.
    """

    # Realistic think time between actions (1–4 seconds).
    wait_time = between(1, 4)

    weight = 4  # 80% of simulated users are authenticated operators

    def on_start(self):
        """Log in once at the start of each simulated session."""
        with self.client.post(
            '/api/v1/auth/login',
            json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD},
            name='POST /auth/login',
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f'login failed: {resp.status_code} {resp.text[:120]}')
                self.token = None
                return
            data = resp.json()
            self.token = data.get('access_token') or data.get('token')
            if not self.token:
                resp.failure('no access_token in login response')

    @property
    def headers(self):
        return {'Authorization': f'Bearer {self.token}'} if self.token else {}

    # ------------------------------------------------------------------
    # Tasks. The @task(N) decorator weights how often each is run.
    # ------------------------------------------------------------------

    @task(10)
    def list_targets(self):
        self.client.get('/api/v1/targets',
                        headers=self.headers,
                        name='GET /targets')

    @task(10)
    def list_attacks(self):
        self.client.get('/api/v1/attacks',
                        headers=self.headers,
                        name='GET /attacks')

    @task(5)
    def whoami(self):
        self.client.get('/api/v1/auth/me',
                        headers=self.headers,
                        name='GET /auth/me')

    @task(3)
    def list_reports(self):
        self.client.get('/api/v1/reports',
                        headers=self.headers,
                        name='GET /reports')

    @task(3)
    def list_campaigns(self):
        self.client.get('/api/v1/campaigns',
                        headers=self.headers,
                        name='GET /campaigns')

    @task(2)
    def list_engagements(self):
        self.client.get('/api/v1/engagements',
                        headers=self.headers,
                        name='GET /engagements')

    @task(2)
    def attack_severities(self):
        self.client.get('/api/v1/attacks/severities',
                        headers=self.headers,
                        name='GET /attacks/severities')

    @task(2)
    def attack_types(self):
        self.client.get('/api/v1/attacks/types',
                        headers=self.headers,
                        name='GET /attacks/types')

    @task(1)
    def audit_log(self):
        self.client.get('/api/v1/audit?limit=20',
                        headers=self.headers,
                        name='GET /audit')


# ---------------------------------------------------------------------------
# Anonymous health probes — small share of total traffic.
# ---------------------------------------------------------------------------

class AnonymousVisitor(HttpUser):
    """Unauthenticated probe traffic (health checks, monitors)."""

    wait_time = between(2, 6)
    weight = 1  # 20% of simulated users

    @task
    def health(self):
        self.client.get('/api/v1/health/ready',
                        name='GET /health/ready')


# ---------------------------------------------------------------------------
# Optional: print a one-line summary at the end of every run for the
# FYP report. Locust already produces full HTML + CSV reports, this
# just gives a quick eyeball check in the terminal.
# ---------------------------------------------------------------------------

@events.test_stop.add_listener
def on_test_stop(environment, **_):
    s = environment.stats.total
    print('\n[locust] summary:')
    print(f'  total requests : {s.num_requests}')
    print(f'  failures       : {s.num_failures}')
    print(f'  median ms      : {s.median_response_time}')
    print(f'  p95 ms         : {s.get_response_time_percentile(0.95)}')
    print(f'  p99 ms         : {s.get_response_time_percentile(0.99)}')
    print(f'  rps (avg)      : {s.total_rps:.1f}')
