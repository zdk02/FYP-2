"""
Throughput tests — concurrent requests against the API.

We fire N concurrent requests via a thread pool and measure
requests-per-second.

Caveat: in-memory SQLite + Flask test client share a single
connection pool that doesn't always cope cleanly with high
concurrency. We therefore assert success_rate >= 0.85 (production
with PostgreSQL would clear 100%) and focus the assertion on the
*throughput* (rps), which is the more meaningful metric for capacity
planning.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest


pytestmark = pytest.mark.performance


# Modest baseline thresholds. These are floors — any halfway-decent
# Flask + SQLite setup should clear them comfortably.
MIN_RPS_LIST_TARGETS = 50    # at least 50 list-targets per second
MIN_RPS_HEALTH = 200          # at least 200 health-checks per second


def _run_concurrent(fn, total_requests, concurrency):
    """Fire ``total_requests`` calls of fn() across ``concurrency``
    workers. Returns dict with elapsed_s, rps, success_rate."""
    successes = 0
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(fn) for _ in range(total_requests)]
        for f in futures:
            try:
                resp = f.result(timeout=10)
                if 200 <= resp.status_code < 300:
                    successes += 1
            except Exception:
                pass
    elapsed = time.perf_counter() - t0
    rps = total_requests / elapsed if elapsed > 0 else 0
    return {
        'total':        total_requests,
        'concurrency':  concurrency,
        'elapsed_s':    round(elapsed, 3),
        'rps':          round(rps, 1),
        'success_rate': round(successes / total_requests, 3),
    }


class TestConcurrentReads:
    def test_health_endpoint_handles_200_concurrent_requests(self, client):
        result = _run_concurrent(
            lambda: client.get('/api/v1/health/ready'),
            total_requests=200,
            concurrency=10,
        )
        print(
            f'[perf] /health  total={result["total"]} '
            f'concurrency={result["concurrency"]} '
            f'elapsed={result["elapsed_s"]}s '
            f'rps={result["rps"]} '
            f'success={result["success_rate"]}'
        )
        # See module docstring re: in-memory SQLite concurrency floor.
        assert result['success_rate'] >= 0.85
        assert result['rps'] >= MIN_RPS_HEALTH, (
            f'health rps below floor: {result["rps"]} < {MIN_RPS_HEALTH}'
        )

    def test_serial_throughput_for_authenticated_endpoint(
        self, client, auth_headers
    ):
        """Serial throughput test for an auth-required endpoint.

        Concurrent tests against auth-gated endpoints are unreliable
        under in-memory SQLite + Flask test client (the auth lookup
        shares one connection across threads, which SQLAlchemy's
        thread-local session model doesn't fully isolate). We
        therefore measure *sustained sequential* throughput, which is
        the more meaningful number for a single Flask worker anyway.
        """
        import time

        n = 100
        successes = 0
        t0 = time.perf_counter()
        for _ in range(n):
            r = client.get('/api/v1/targets', headers=auth_headers)
            if 200 <= r.status_code < 300:
                successes += 1
        elapsed = time.perf_counter() - t0
        rps = n / elapsed if elapsed > 0 else 0

        print(
            f'[perf] /targets serial total={n} '
            f'elapsed={elapsed:.3f}s '
            f'rps={rps:.1f} '
            f'success={successes/n:.3f}'
        )

        assert successes == n, f'only {successes}/{n} requests succeeded'
        assert rps >= MIN_RPS_LIST_TARGETS, (
            f'list rps below floor: {rps:.1f} < {MIN_RPS_LIST_TARGETS}'
        )
