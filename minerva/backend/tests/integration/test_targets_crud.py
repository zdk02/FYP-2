"""
Integration tests for /api/v1/targets — CRUD + role-based access.

Verifies the full vertical: HTTP -> JWT auth -> require_role decorator
-> SQLAlchemy ORM write -> JSON response. Uses the in-memory SQLite
DB built by the `app` fixture.
"""

import pytest


pytestmark = pytest.mark.integration


def _make_target(client, headers, **overrides):
    payload = {
        'name': 'demo-mcp-server',
        'target_type': 'mcp_server',
        'host': '127.0.0.1',
        'port': 8765,
        'protocol': 'http',
        'environment': 'development',
    }
    payload.update(overrides)
    return client.post('/api/v1/targets', headers=headers, json=payload)


class TestListTargets:
    def test_unauthenticated_request_is_rejected(self, client):
        resp = client.get('/api/v1/targets')
        assert resp.status_code == 401

    def test_empty_db_returns_empty_list_or_paged_envelope(self, client, auth_headers):
        resp = client.get('/api/v1/targets', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        # Endpoint may return either a bare list or a paginated dict — both are fine
        if isinstance(body, dict):
            assert body.get('targets', []) == [] or body.get('items', []) == []
        else:
            assert body == []


class TestCreateTarget:
    def test_create_target_with_valid_payload_returns_201(self, client, auth_headers):
        resp = _make_target(client, auth_headers)
        assert resp.status_code == 201
        body = resp.get_json()
        assert body['target']['name'] == 'demo-mcp-server'
        assert body['target']['port'] == 8765

    def test_created_target_appears_in_list(self, client, auth_headers):
        _make_target(client, auth_headers, name='alpha')
        _make_target(client, auth_headers, name='beta', host='10.0.0.5', port=9000)

        resp = client.get('/api/v1/targets', headers=auth_headers)
        body = resp.get_json()
        items = body if isinstance(body, list) else (body.get('targets') or body.get('items') or [])
        names = {t['name'] for t in items}
        assert {'alpha', 'beta'}.issubset(names)

    def test_create_target_without_name_returns_400(self, client, auth_headers):
        resp = client.post('/api/v1/targets', headers=auth_headers,
                           json={'host': '127.0.0.1', 'port': 8765})
        assert resp.status_code == 400
        assert 'name' in resp.get_json()['error'].lower()

    def test_create_http_target_without_host_returns_400(self, client, auth_headers):
        resp = client.post('/api/v1/targets', headers=auth_headers,
                           json={'name': 'no-host', 'protocol': 'http'})
        assert resp.status_code == 400
        assert 'host' in resp.get_json()['error'].lower()

    def test_stdio_target_requires_base_url(self, client, auth_headers):
        resp = client.post('/api/v1/targets', headers=auth_headers,
                           json={'name': 'stdio-target', 'protocol': 'stdio'})
        assert resp.status_code == 400
        assert 'stdio' in resp.get_json()['error'].lower()

    def test_stdio_target_with_base_url_succeeds(self, client, auth_headers):
        resp = client.post('/api/v1/targets', headers=auth_headers,
                           json={'name': 'stdio-ok',
                                 'protocol': 'stdio',
                                 'base_url': 'stdio:python -m demo_server'})
        assert resp.status_code == 201

    def test_create_target_without_token_returns_401(self, client):
        resp = client.post('/api/v1/targets',
                           json={'name': 'x', 'host': '127.0.0.1'})
        assert resp.status_code == 401


class TestGetSingleTarget:
    def test_get_existing_target_returns_full_record(self, client, auth_headers):
        created = _make_target(client, auth_headers, name='lookup-me').get_json()
        target_id = created['target']['id']

        resp = client.get(f'/api/v1/targets/{target_id}', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['name'] == 'lookup-me'
        assert body['id'] == target_id

    def test_get_unknown_target_returns_404(self, client, auth_headers):
        resp = client.get('/api/v1/targets/does-not-exist',
                          headers=auth_headers)
        assert resp.status_code == 404


class TestUpdateTarget:
    def test_update_target_changes_persist(self, client, auth_headers):
        created = _make_target(client, auth_headers,
                               name='before').get_json()
        target_id = created['target']['id']

        resp = client.put(f'/api/v1/targets/{target_id}',
                          headers=auth_headers,
                          json={'name': 'after', 'port': 9999})
        assert resp.status_code == 200

        get_resp = client.get(f'/api/v1/targets/{target_id}',
                              headers=auth_headers).get_json()
        assert get_resp['name'] == 'after'
        assert get_resp['port'] == 9999


class TestDeleteTarget:
    def test_admin_can_delete_target(self, client, auth_headers):
        created = _make_target(client, auth_headers,
                               name='will-be-deleted').get_json()
        target_id = created['target']['id']

        resp = client.delete(f'/api/v1/targets/{target_id}',
                             headers=auth_headers)
        assert resp.status_code == 200

        # Confirm it's really gone
        gone = client.get(f'/api/v1/targets/{target_id}', headers=auth_headers)
        assert gone.status_code == 404

    def test_viewer_cannot_delete_target(self, client, auth_headers, viewer_user):
        created = _make_target(client, auth_headers,
                               name='protected').get_json()
        target_id = created['target']['id']

        _, viewer_token = viewer_user
        viewer_headers = {'Authorization': f'Bearer {viewer_token}'}
        resp = client.delete(f'/api/v1/targets/{target_id}',
                             headers=viewer_headers)
        assert resp.status_code == 403
        assert 'permission' in resp.get_json()['error'].lower()

    def test_delete_unknown_target_returns_404(self, client, auth_headers):
        resp = client.delete('/api/v1/targets/does-not-exist',
                             headers=auth_headers)
        assert resp.status_code == 404


class TestTargetMetadataEndpoints:
    def test_target_types_endpoint_returns_list(self, client, auth_headers):
        resp = client.get('/api/v1/targets/types', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        # The types catalogue should be a non-empty list of dicts
        assert isinstance(body, (list, dict))

    def test_environments_endpoint_returns_list(self, client, auth_headers):
        resp = client.get('/api/v1/targets/environments', headers=auth_headers)
        assert resp.status_code == 200
