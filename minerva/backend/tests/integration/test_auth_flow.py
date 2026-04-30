"""
Integration tests for the JWT auth flow.

Exercises the full chain: HTTP request -> Flask blueprint -> SQLAlchemy
User lookup -> bcrypt password check -> Flask-JWT-Extended token mint
-> response. The seeded admin user (admin@minerva.local / admin123) is
created automatically by `initialize_default_data()` when the test app
is built.
"""

import pytest


pytestmark = pytest.mark.integration


class TestLogin:
    def test_login_with_correct_credentials_returns_tokens(self, client):
        resp = client.post('/api/v1/auth/login',
                           json={'email': 'admin@minerva.local',
                                 'password': 'admin123'})
        assert resp.status_code == 200
        body = resp.get_json()
        assert 'access_token' in body
        assert 'refresh_token' in body
        assert body['user']['email'] == 'admin@minerva.local'
        assert body['user']['role'] == 'admin'

    def test_login_accepts_username_field(self, client):
        resp = client.post('/api/v1/auth/login',
                           json={'username': 'admin', 'password': 'admin123'})
        assert resp.status_code == 200
        assert 'access_token' in resp.get_json()

    def test_login_with_wrong_password_returns_401(self, client):
        resp = client.post('/api/v1/auth/login',
                           json={'email': 'admin@minerva.local',
                                 'password': 'WRONG'})
        assert resp.status_code == 401
        assert resp.get_json()['error'] == 'Invalid credentials'

    def test_login_with_unknown_email_returns_401(self, client):
        resp = client.post('/api/v1/auth/login',
                           json={'email': 'nobody@nowhere.com',
                                 'password': 'whatever'})
        assert resp.status_code == 401

    def test_login_without_password_returns_400(self, client):
        resp = client.post('/api/v1/auth/login',
                           json={'email': 'admin@minerva.local'})
        assert resp.status_code == 400
        assert 'required' in resp.get_json()['error'].lower()

    def test_login_with_empty_payload_returns_400(self, client):
        resp = client.post('/api/v1/auth/login', json={})
        assert resp.status_code == 400


class TestMeEndpoint:
    def test_me_returns_user_info_with_valid_token(self, client, auth_headers):
        resp = client.get('/api/v1/auth/me', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['email'] == 'admin@minerva.local'
        assert body['role'] == 'admin'
        assert body['is_active'] is True

    def test_me_without_token_returns_401(self, client):
        resp = client.get('/api/v1/auth/me')
        assert resp.status_code == 401

    def test_me_with_garbage_token_returns_422(self, client):
        resp = client.get('/api/v1/auth/me',
                          headers={'Authorization': 'Bearer not-a-real-token'})
        # Flask-JWT-Extended returns 422 for malformed tokens
        assert resp.status_code in (401, 422)


class TestRefresh:
    def test_refresh_token_yields_new_access_token(self, client):
        login = client.post('/api/v1/auth/login',
                            json={'email': 'admin@minerva.local',
                                  'password': 'admin123'}).get_json()
        refresh_headers = {'Authorization': f'Bearer {login["refresh_token"]}'}

        resp = client.post('/api/v1/auth/refresh', headers=refresh_headers)
        assert resp.status_code == 200
        new_access = resp.get_json()['access_token']
        assert isinstance(new_access, str) and len(new_access) > 20

    def test_refresh_with_access_token_is_rejected(self, client, auth_headers):
        # Using the access token (not refresh) on /refresh must fail.
        resp = client.post('/api/v1/auth/refresh', headers=auth_headers)
        assert resp.status_code in (401, 422)


class TestLogout:
    def test_logout_with_valid_token_returns_200(self, client, auth_headers):
        resp = client.post('/api/v1/auth/logout', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['message'] == 'Logged out successfully'

    def test_logout_without_token_returns_401(self, client):
        resp = client.post('/api/v1/auth/logout')
        assert resp.status_code == 401


class TestChangePassword:
    def test_change_password_succeeds_with_correct_current_password(
        self, client, auth_headers
    ):
        resp = client.post(
            '/api/v1/auth/change-password',
            headers=auth_headers,
            json={'current_password': 'admin123', 'new_password': 'newpass456'},
        )
        assert resp.status_code == 200
        # The new password should now log in
        login = client.post('/api/v1/auth/login',
                            json={'email': 'admin@minerva.local',
                                  'password': 'newpass456'})
        assert login.status_code == 200

    def test_change_password_with_wrong_current_returns_400(
        self, client, auth_headers
    ):
        resp = client.post(
            '/api/v1/auth/change-password',
            headers=auth_headers,
            json={'current_password': 'WRONG', 'new_password': 'newpass456'},
        )
        assert resp.status_code == 400

    def test_change_password_without_token_returns_401(self, client):
        resp = client.post('/api/v1/auth/change-password',
                           json={'current_password': 'a', 'new_password': 'b'})
        assert resp.status_code == 401
