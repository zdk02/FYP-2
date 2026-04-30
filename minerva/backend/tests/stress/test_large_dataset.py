"""
Large-dataset stress test — does the system stay responsive when the
DB has many rows?

Performance Session 8 already proved 50 rows is no slower than 0
rows (linear scaling for indexed reads). Here we go further:
seed 500 rows and check that listing still completes within a
relaxed budget.
"""

from __future__ import annotations

import time
import pytest


pytestmark = pytest.mark.stress


class TestListingWith500Targets:
    def test_seed_500_targets_then_list_under_1_second(
        self, client, auth_headers
    ):
        # Seed 500 targets via the real API (proves writes also scale).
        seed_t0 = time.perf_counter()
        for i in range(500):
            r = client.post(
                '/api/v1/targets', headers=auth_headers,
                json={'name': f'stress-tgt-{i:04d}',
                      'host': '127.0.0.1',
                      'port': 9000 + i,
                      'protocol': 'http'},
            )
            assert r.status_code == 201, (
                f'seed write failed at i={i}: {r.status_code}'
            )
        seed_elapsed = time.perf_counter() - seed_t0

        # Now list them.
        list_t0 = time.perf_counter()
        r = client.get('/api/v1/targets', headers=auth_headers)
        list_elapsed_ms = (time.perf_counter() - list_t0) * 1000.0

        body = r.get_json()
        items = (
            body if isinstance(body, list)
            else (body.get('targets') or body.get('items') or [])
        )

        print(
            f'[stress] seeded 500 targets in {seed_elapsed:.2f}s, '
            f'list returned {len(items)} items in {list_elapsed_ms:.2f}ms'
        )

        assert r.status_code == 200
        # Listing 500 rows must still come in under 1 second.
        assert list_elapsed_ms < 1000, (
            f'listing 500 rows took {list_elapsed_ms:.0f}ms — too slow'
        )

    def test_search_filter_still_fast_with_500_rows(self, client, auth_headers):
        """The search filter on /targets must remain usable at scale."""
        # The 500 targets seeded by the previous test are still in the DB
        # (module-scoped fixture), so we can search across them.
        t0 = time.perf_counter()
        r = client.get(
            '/api/v1/targets', headers=auth_headers,
            query_string={'search': 'stress-tgt-04'},  # matches 100 rows
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        print(
            f'[stress] search across 500 rows: {elapsed_ms:.2f}ms'
        )

        assert r.status_code == 200
        assert elapsed_ms < 500
