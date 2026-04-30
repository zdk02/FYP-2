"""
Unit tests for app.services.attack_helpers — schema and tool helpers
shared by every refined attack script.
"""

import pytest

from app.services import attack_helpers


pytestmark = pytest.mark.unit


class TestStringParams:
    def test_returns_only_string_typed_properties(self):
        schema = {
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
                "city": {"type": "string"},
            }
        }
        out = attack_helpers.string_params(schema)
        assert set(out) == {"name", "city"}

    def test_empty_schema_returns_empty_list(self):
        assert attack_helpers.string_params({}) == []

    def test_none_schema_safe(self):
        assert attack_helpers.string_params(None) == []


class TestAllParamNames:
    def test_returns_every_property_name(self):
        schema = {"properties": {"a": {}, "b": {}, "c": {}}}
        assert set(attack_helpers.all_param_names(schema)) == {"a", "b", "c"}

    def test_none_schema_safe(self):
        assert attack_helpers.all_param_names(None) == []


class TestFillDefaults:
    def test_fills_required_string_with_default(self):
        schema = {
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        }
        out = attack_helpers.fill_defaults(schema, default_string="probe")
        assert out == {"q": "probe"}

    def test_fills_required_integer_with_one(self):
        schema = {"properties": {"n": {"type": "integer"}}, "required": ["n"]}
        out = attack_helpers.fill_defaults(schema)
        assert out == {"n": 1}

    def test_fills_required_boolean_with_false(self):
        schema = {"properties": {"flag": {"type": "boolean"}}, "required": ["flag"]}
        out = attack_helpers.fill_defaults(schema)
        assert out == {"flag": False}

    def test_skips_optional_fields(self):
        schema = {
            "properties": {"req": {"type": "string"}, "opt": {"type": "string"}},
            "required": ["req"],
        }
        out = attack_helpers.fill_defaults(schema)
        assert "req" in out
        assert "opt" not in out


class TestPickByKeywords:
    def test_picks_tools_with_matching_keywords_in_name(self):
        tools = [
            {"name": "search_db", "description": "Run a query"},
            {"name": "send_email", "description": "Send mail"},
            {"name": "exec_cmd", "description": "Execute a shell command"},
        ]
        out = attack_helpers.pick_by_keywords(tools, ("exec", "shell"))
        assert any(t["name"] == "exec_cmd" for t in out)

    def test_name_matches_score_higher_than_desc_matches(self):
        tools = [
            {"name": "other", "description": "this tool can exec commands"},
            {"name": "exec", "description": "unrelated description"},
        ]
        out = attack_helpers.pick_by_keywords(tools, ("exec",))
        # "exec" in name should be ranked first
        assert out[0]["name"] == "exec"

    def test_force_names_filters_strictly(self):
        tools = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        out = attack_helpers.pick_by_keywords(
            tools, ("anything",), force_names=["b", "c"]
        )
        assert {t["name"] for t in out} == {"b", "c"}

    def test_no_match_returns_empty_when_fallback_false(self):
        tools = [{"name": "a", "description": "x"}]
        out = attack_helpers.pick_by_keywords(tools, ("nope",), fallback_all=False)
        assert out == []

    def test_no_match_returns_all_when_fallback_true(self):
        tools = [{"name": "a", "description": "x"}, {"name": "b", "description": "y"}]
        out = attack_helpers.pick_by_keywords(tools, ("nope",), fallback_all=True)
        assert len(out) == 2
