"""
Burst load — fire many requests in quick succession at the API.

These are not the same as performance tests. Performance asks "is
the system fast enough under normal load." Stress asks "what
happens when we go past normal."

Pass criteria:
  - The server does not crash (no exceptions propagate up).
  - Success rate stays above a degraded-but-functional floor.
  - Throughput stays above zero (proves there's no deadlock).
"""

from __future__ import annotations

import time
import pytest


pytestmark = pytest.mark.stress


class TestBurstLoadOnHealth:
    """The cheapest endpoint — should sustain very high burst load."""

    def test_1000_burst_health_requests_succeed(self, client):
        n = 1000
        successes = 0
        t0 = time.perf_counter()
        for _ in range(n):
            r = client.get('/api/v1/health/ready')
            if r.status_code == 200:
                successes += 1
        elapsed = time.perf_counter() - t0
        rps = n / elapsed if elapsed > 0 else 0

        print(
            f'[stress] /health burst total={n} elapsed={elapsed:.2f}s '
            f'rps={rps:.0f} success={successes/n:.3f}'
        )

        # Stress floor: at least 99% success and at least 200 rps.
        assert successes >= int(n * 0.99), (
            f'too many failures under burst: {n - successes}/{n}'
        )
        assert rps >= 200


class TestBurstLoadOnAuthenticatedEndpoint:
    """An auth-required, DB-touching endpoint under sustained burst."""

    def test_500_burst_targets_requests_stay_functional(
        self, client, auth_headers
    ):
        n = 500
        successes = 0
        latencies = []
        t0 = time.perf_counter()
        for _ in range(n):
            req_t0 = time.perf_counter()
            r = client.get('/api/v1/targets', headers=auth_headers)
            latencies.append((time.perf_counter() - req_t0) * 1000.0)
            if 200 <= r.status_code < 300:
                successes += 1
        elapsed = time.perf_counter() - t0
        rps = n / elapsed if elapsed > 0 else 0

        # Tail latency under burst.
        latencies.sort()
        p99_ms = latencies[int(n * 0.99) - 1] if n >= 100 else max(latencies)

        print(
            f'[stress] /targets burst total={n} elapsed={elapsed:.2f}s '
            f'rps={rps:.0f} success={successes/n:.3f} p99={p99_ms:.2f}ms'
        )

        assert successes == n, f'unexpected failures: {n - successes}/{n}'
        # Even under burst, p99 should stay reasonable (<200ms).
        assert p99_ms < 200, f'p99 latency degraded under burst: {p99_ms:.2f}ms'


class TestRapidLoginBurstDoesNotCrash:
    """bcrypt is intentionally CPU-heavy. Hammering /auth/login is a
    legitimate stress on CPU. We don't expect 1000 logins/sec, but
    we do expect the server to remain stable and not OOM/segfault."""

    def test_30_consecutive_logins_all_succeed(self, client):
        n = 30
        successes = 0
        t0 = time.perf_counter()
        for _ in range(n):
            r = client.post('/api/v1/auth/login',
                            json={'email': 'admin@minerva.local',
                                  'password': 'admin123'})
            if r.status_code == 200:
                successes += 1
        elapsed = time.perf_counter() - t0
        rps = n / elapsed if elapsed > 0 else 0

        print(
            f'[stress] /auth/login burst total={n} elapsed={elapsed:.2f}s '
            f'rps={rps:.1f} success={successes/n:.3f}'
        )
        assert successes == n
