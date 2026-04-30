"""
Large-payload stress tests — does the API stay stable when given
unusually large inputs?

Goal: confirm the server doesn't crash, hang, or leak data when fed
oversized requests. The acceptance bar is "graceful response" —
either the server accepts the input within Flask's MAX_CONTENT_LENGTH
(50 MB), or rejects it with a clean 4xx. Anything that returns 500
or hangs is a stress failure.
"""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.stress


class TestOversizedTargetFields:
    def test_10kb_target_name_is_handled_gracefully(self, client, auth_headers):
        big_name = 'A' * 10_000
        r = client.post(
            '/api/v1/targets', headers=auth_headers,
            json={'name': big_name, 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http'},
        )
        # 201 (accepted), 400 (rejected — too long), or 413 (payload too large).
        assert r.status_code in (201, 400, 413), f'unexpected: {r.status_code}'
        assert r.status_code != 500

    def test_100kb_description_is_handled_gracefully(self, client, auth_headers):
        big_desc = 'X' * 100_000
        r = client.post(
            '/api/v1/targets', headers=auth_headers,
            json={'name': 'desc-test', 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http',
                  'description': big_desc},
        )
        assert r.status_code in (201, 400, 413)
        assert r.status_code != 500

    def test_1mb_payload_does_not_crash_server(self, client, auth_headers):
        # 1 MB is well below Flask's 50 MB MAX_CONTENT_LENGTH default.
        big_blob = 'Y' * 1_000_000
        r = client.post(
            '/api/v1/targets', headers=auth_headers,
            json={'name': 'mb-test', 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http',
                  'description': big_blob},
        )
        assert r.status_code != 500


class TestDeeplyNestedJson:
    def test_deeply_nested_auth_config_does_not_crash(
        self, client, auth_headers
    ):
        # Build a 50-level nested dict. Most JSON parsers cap recursion
        # well above this, so it should parse fine — just stress-checks
        # the validation layer doesn't choke.
        nested = {'type': 'custom', 'headers': {}}
        cur = nested['headers']
        for i in range(50):
            cur[f'level_{i}'] = {}
            cur = cur[f'level_{i}']
        cur['final'] = 'value'

        r = client.post(
            '/api/v1/targets', headers=auth_headers,
            json={'name': 'nested', 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http',
                  'auth_config': nested},
        )
        assert r.status_code != 500


class TestManyQueryParams:
    def test_50_query_params_does_not_break_listing(self, client, auth_headers):
        # Spray 50 unrecognised query params at /targets.
        params = {f'unknown_{i}': f'value_{i}' for i in range(50)}
        params['search'] = 'test'  # one real param mixed in
        r = client.get('/api/v1/targets', headers=auth_headers,
                       query_string=params)
        assert r.status_code == 200
