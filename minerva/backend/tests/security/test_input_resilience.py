"""
Input-resilience tests.

The API must handle hostile inputs gracefully — never 500, never run
the payload, never corrupt the database. We don't expect creative
output here; we expect either a 200/4xx clean response, or stored
data that contains the literal payload as a harmless string.

Note: the project explicitly disclaims being a hardened production
service — these tests pin the *current* defensible behaviour rather
than asserting the system is hack-proof.
"""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.security


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT NULL, NULL, NULL --",
    "admin' --",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert('xss')",
    "<svg/onload=alert(1)>",
]


class TestSqlInjectionResilience:
    @pytest.mark.parametrize('payload', SQLI_PAYLOADS)
    def test_sqli_in_targets_search_does_not_break_query(
        self, client, admin_headers, payload
    ):
        """The ?search= filter on /targets is built with SQLAlchemy's
        ``.ilike()`` parameterised binding — SQLi payloads must come
        back as a normal 200, not a 500 or a DB error."""
        resp = client.get(
            '/api/v1/targets', headers=admin_headers,
            query_string={'search': payload},
        )
        assert resp.status_code == 200, (
            f'search parameter caused {resp.status_code} for payload {payload!r}'
        )

    @pytest.mark.parametrize('payload', SQLI_PAYLOADS)
    def test_sqli_in_attacks_search_does_not_break_query(
        self, client, admin_headers, payload
    ):
        resp = client.get(
            '/api/v1/attacks', headers=admin_headers,
            query_string={'search': payload},
        )
        assert resp.status_code == 200

    def test_login_with_sqli_in_email_returns_clean_401(self, client):
        """A textbook SQLi login bypass must NOT succeed and must NOT
        crash the server."""
        resp = client.post(
            '/api/v1/auth/login',
            json={'email': "admin' OR '1'='1", 'password': 'whatever'},
        )
        assert resp.status_code == 401  # not 200, not 500


class TestXssStoragePassesThrough:
    """The backend stores user-supplied strings verbatim (it's a JSON API,
    not an HTML renderer). We assert the server doesn't crash and the
    payload round-trips as-is — frontend escaping is what prevents XSS
    in the rendered DOM."""

    @pytest.mark.parametrize('payload', XSS_PAYLOADS)
    def test_xss_payload_in_target_name_is_stored_and_returned_unchanged(
        self, client, admin_headers, payload
    ):
        create = client.post(
            '/api/v1/targets', headers=admin_headers,
            json={'name': payload, 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http'},
        )
        assert create.status_code == 201
        target_id = create.get_json()['target']['id']

        get = client.get(f'/api/v1/targets/{target_id}', headers=admin_headers)
        assert get.status_code == 200
        assert get.get_json()['name'] == payload  # stored verbatim


class TestOversizedAndMalformedInput:
    def test_extremely_long_target_name_does_not_500(self, client, admin_headers):
        # 5000-char name. We don't pin a specific status — 201/400/413 are
        # all defensible. We just require it doesn't crash with a 500.
        long_name = 'A' * 5000
        resp = client.post(
            '/api/v1/targets', headers=admin_headers,
            json={'name': long_name, 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http'},
        )
        assert resp.status_code != 500

    def test_unicode_and_null_bytes_in_input_do_not_crash(self, client, admin_headers):
        weird = 'naïve\x00‮target'
        resp = client.post(
            '/api/v1/targets', headers=admin_headers,
            json={'name': weird, 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http'},
        )
        assert resp.status_code != 500

    def test_invalid_json_body_returns_4xx_not_500(self, client, admin_headers):
        resp = client.post(
            '/api/v1/targets',
            headers={**admin_headers, 'Content-Type': 'application/json'},
            data='this is not json{{{',
        )
        assert 400 <= resp.status_code < 500
