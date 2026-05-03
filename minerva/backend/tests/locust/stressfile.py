"""
Minerva — Locust STRESS test.

Where the perf locustfile (locustfile.py) simulates realistic users
with 1-4 second think time, this stress file hammers the server with
**zero think time** and high concurrency to find the breaking point.

Pass criteria are deliberately loose — the goal is graceful
degradation, not perfection:

  * Server stays up (no crashes / hung process)
  * Success rate stays above a "degraded-but-functional" floor
  * Throughput remains positive (no deadlock)

Run scenarios:

  # Spike: 200 users sustained for 2 minutes, no ramp delay
  python -m locust -f tests/locust/stressfile.py \\
    --host http://127.0.0.1:5000 --headless \\
    -u 200 -r 50 -t 2m \\
    --html reports/locust/stress_spike.html \\
    --csv reports/locust/stress_spike

  # Step load: ramp 0 → 300 users over 3 minutes — find the knee
  python -m locust -f tests/locust/stressfile.py \\
    --host http://127.0.0.1:5000 --headless \\
    -u 300 -r 2 -t 3m \\
    --html reports/locust/stress_step.html \\
    --csv reports/locust/stress_step

NOTE: always use ``127.0.0.1`` not ``localhost`` on Windows
(IPv6 resolution adds a 2 s timeout per request).
"""

from __future__ import annotations

from locust import HttpUser, task, constant, events


ADMIN_EMAIL = 'admin@minerva.local'
ADMIN_PASSWORD = 'admin123'


class StressUser(HttpUser):
    """Zero-think-time hammer.

    Logs in once (so we don't spend the whole stress run hitting the
    intentionally-slow bcrypt KDF), then fires authenticated reads
    as fast as the server will accept them.
    """

    # constant(0) = no wait between tasks. This is the stress signature.
    wait_time = constant(0)

    def on_start(self):
        with self.client.post(
            '/api/v1/auth/login',
            json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD},
            name='POST /auth/login',
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(
                    f'login failed: {resp.status_code} {resp.text[:120]}')
                self.token = None
                return
            data = resp.json()
            self.token = data.get('access_token') or data.get('token')

    @property
    def headers(self):
        return {'Authorization': f'Bearer {self.token}'} if self.token else {}

    # ------------------------------------------------------------------
    # Mix of cheap + DB-touching endpoints. No write tasks (must be
    # idempotent so we can rerun safely).
    # ------------------------------------------------------------------

    @task(5)
    def health(self):
        self.client.get('/api/v1/health/ready', name='GET /health/ready')

    @task(3)
    def list_targets(self):
        self.client.get('/api/v1/targets',
                        headers=self.headers, name='GET /targets')

    @task(3)
    def list_attacks(self):
        self.client.get('/api/v1/attacks',
                        headers=self.headers, name='GET /attacks')

    @task(2)
    def whoami(self):
        self.client.get('/api/v1/auth/me',
                        headers=self.headers, name='GET /auth/me')


@events.test_stop.add_listener
def on_test_stop(environment, **_):
    s = environment.stats.total
    print('\n[stress] summary:')
    print(f'  total requests : {s.num_requests}')
    print(f'  failures       : {s.num_failures}')
    print(f'  failure rate   : {s.fail_ratio:.2%}')
    print(f'  median ms      : {s.median_response_time}')
    print(f'  p95 ms         : {s.get_response_time_percentile(0.95)}')
    print(f'  p99 ms         : {s.get_response_time_percentile(0.99)}')
    print(f'  rps (avg)      : {s.total_rps:.1f}')

    # Stress acceptance bar — graceful degradation, not perfection.
    if s.fail_ratio > 0.05:
        print(f'  ⚠ failure rate above 5% — investigate for crashes')
    if s.total_rps < 10:
        print(f'  ⚠ rps below 10 — possible deadlock')
