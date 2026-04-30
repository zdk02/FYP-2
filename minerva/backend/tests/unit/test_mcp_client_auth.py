"""
Unit tests for app.services.mcp_client.apply_auth().

apply_auth() composes HTTP headers from a Target.auth_config dict.
It must support 5 auth types (bearer, api_key, basic, oauth2, custom)
and degrade gracefully on bad input.

These tests are pure-function: no network, no DB, no Flask context.
"""

import base64

import pytest

from app.services import mcp_client


pytestmark = pytest.mark.unit


class TestBearerAuth:
    def test_bearer_token_sets_authorization_header(self):
        h = mcp_client.apply_auth({}, {"type": "bearer", "token": "abc123"})
        assert h["Authorization"] == "Bearer abc123"

    def test_oauth2_uses_same_bearer_format(self):
        h = mcp_client.apply_auth({}, {"type": "oauth2", "token": "xyz"})
        assert h["Authorization"] == "Bearer xyz"

    def test_jwt_uses_same_bearer_format(self):
        h = mcp_client.apply_auth({}, {"type": "jwt", "token": "eyJabc"})
        assert h["Authorization"] == "Bearer eyJabc"

    def test_bearer_falls_back_to_value_field(self):
        h = mcp_client.apply_auth({}, {"type": "bearer", "value": "fallback"})
        assert h["Authorization"] == "Bearer fallback"

    def test_bearer_with_empty_token_omits_header(self):
        h = mcp_client.apply_auth({}, {"type": "bearer", "token": ""})
        assert "Authorization" not in h


class TestApiKeyAuth:
    def test_api_key_sets_named_header(self):
        h = mcp_client.apply_auth({}, {"type": "api_key", "header": "X-K", "value": "secret"})
        assert h["X-K"] == "secret"

    def test_api_key_defaults_to_x_api_key_header(self):
        h = mcp_client.apply_auth({}, {"type": "api_key", "value": "v"})
        assert h["X-API-Key"] == "v"

    def test_apikey_alias_works(self):
        h = mcp_client.apply_auth({}, {"type": "apikey", "value": "v"})
        assert h["X-API-Key"] == "v"


class TestBasicAuth:
    def test_basic_auth_encodes_username_password(self):
        h = mcp_client.apply_auth({}, {"type": "basic", "username": "alice", "password": "pw"})
        expected = "Basic " + base64.b64encode(b"alice:pw").decode()
        assert h["Authorization"] == expected

    def test_basic_auth_with_empty_credentials_still_encodes(self):
        h = mcp_client.apply_auth({}, {"type": "basic"})
        expected = "Basic " + base64.b64encode(b":").decode()
        assert h["Authorization"] == expected


class TestCustomAuth:
    def test_custom_headers_added(self):
        h = mcp_client.apply_auth(
            {}, {"type": "custom", "headers": {"X-Sig": "abc", "X-Tenant": "t1"}}
        )
        assert h["X-Sig"] == "abc"
        assert h["X-Tenant"] == "t1"

    def test_custom_headers_coerced_to_strings(self):
        h = mcp_client.apply_auth({}, {"type": "custom", "headers": {"X-N": 42}})
        assert h["X-N"] == "42"


class TestNoneAndEdgeCases:
    def test_none_type_returns_unchanged_headers(self):
        h = mcp_client.apply_auth({"X-Existing": "yes"}, {"type": "none"})
        assert h == {"X-Existing": "yes"}

    def test_empty_auth_config_returns_unchanged(self):
        h = mcp_client.apply_auth({"A": "1"}, {})
        assert h == {"A": "1"}

    def test_none_auth_config_returns_unchanged(self):
        h = mcp_client.apply_auth({"A": "1"}, None)
        assert h == {"A": "1"}

    def test_string_json_auth_config_is_parsed(self):
        h = mcp_client.apply_auth({}, '{"type": "bearer", "token": "from-string"}')
        assert h["Authorization"] == "Bearer from-string"

    def test_malformed_string_auth_config_returns_unchanged(self):
        h = mcp_client.apply_auth({"k": "v"}, "not-json{{{")
        assert h == {"k": "v"}

    def test_non_dict_non_string_auth_config_returns_unchanged(self):
        h = mcp_client.apply_auth({"k": "v"}, 12345)
        assert h == {"k": "v"}

    def test_does_not_mutate_input_headers(self):
        original = {"K": "v"}
        mcp_client.apply_auth(original, {"type": "bearer", "token": "t"})
        assert original == {"K": "v"}
