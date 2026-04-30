"""
Unit tests for app.services.cve_schema validation.

Scanner-plugin YAML files are user-editable. The validator is the
contract that protects the runtime from malformed CVE entries.
Each validate_* function raises ValidationError on bad input and
returns silently on good input.
"""

import pytest

from app.services import cve_schema
from app.services.cve_schema import ValidationError


pytestmark = pytest.mark.unit


class TestValidateCheck:
    def test_valid_file_exists_check_passes(self):
        cve_schema.validate_check({"type": "file_exists", "path": "/etc/passwd"})

    def test_unknown_check_type_rejected(self):
        with pytest.raises(ValidationError, match="unknown check type"):
            cve_schema.validate_check({"type": "psychic_scan"})

    def test_missing_required_field_rejected(self):
        with pytest.raises(ValidationError, match="missing required"):
            cve_schema.validate_check({"type": "file_exists"})

    def test_check_must_be_object(self):
        with pytest.raises(ValidationError, match="must be an object"):
            cve_schema.validate_check("not-a-dict")

    def test_missing_type_rejected(self):
        with pytest.raises(ValidationError, match="check.type is required"):
            cve_schema.validate_check({})


class TestValidateCve:
    def _valid_cve(self):
        return {
            "id": "CVE-2024-0001",
            "title": "Demo vuln",
            "severity": "high",
            "description": "demo",
        }

    def test_valid_cve_passes(self):
        cve_schema.validate_cve(self._valid_cve())

    def test_invalid_cve_id_format_rejected(self):
        cve = self._valid_cve()
        cve["id"] = "not a cve"
        with pytest.raises(ValidationError, match="cve.id must match"):
            cve_schema.validate_cve(cve)

    def test_invalid_severity_rejected(self):
        cve = self._valid_cve()
        cve["severity"] = "apocalyptic"
        with pytest.raises(ValidationError, match="severity must be one of"):
            cve_schema.validate_cve(cve)

    def test_cvss_out_of_range_rejected(self):
        cve = self._valid_cve()
        cve["cvss"] = 11.0
        with pytest.raises(ValidationError, match="cvss must be a number"):
            cve_schema.validate_cve(cve)

    def test_cvss_non_numeric_rejected(self):
        cve = self._valid_cve()
        cve["cvss"] = "not-a-number"
        with pytest.raises(ValidationError, match="cvss must be a number"):
            cve_schema.validate_cve(cve)

    def test_references_must_be_list(self):
        cve = self._valid_cve()
        cve["references"] = "https://x"
        with pytest.raises(ValidationError, match="references must be a list"):
            cve_schema.validate_cve(cve)

    def test_active_checks_must_be_list(self):
        cve = self._valid_cve()
        cve["active_checks"] = "not a list"
        with pytest.raises(ValidationError, match="active_checks must be a list"):
            cve_schema.validate_cve(cve)

    def test_invalid_nested_check_rejected(self):
        cve = self._valid_cve()
        cve["env_checks"] = [{"type": "psychic_scan"}]
        with pytest.raises(ValidationError, match="unknown check type"):
            cve_schema.validate_cve(cve)


class TestValidateClient:
    def _valid_client(self):
        return {
            "display_name": "Claude Code",
            "vendor": "Anthropic",
            "type": "cli",
        }

    def test_valid_client_passes(self):
        cve_schema.validate_client(self._valid_client())

    def test_invalid_client_type_rejected(self):
        client = self._valid_client()
        client["type"] = "spaceship"
        with pytest.raises(ValidationError, match="client.type must be one of"):
            cve_schema.validate_client(client)

    def test_duplicate_cve_ids_rejected(self):
        client = self._valid_client()
        client["cves"] = [
            {"id": "CVE-2024-1", "title": "a", "severity": "high", "description": "d"},
            {"id": "CVE-2024-1", "title": "b", "severity": "low", "description": "d"},
        ]
        with pytest.raises(ValidationError, match="duplicate CVE id"):
            cve_schema.validate_client(client)

    def test_missing_display_name_rejected(self):
        client = {"vendor": "v", "type": "cli"}
        with pytest.raises(ValidationError, match="display_name"):
            cve_schema.validate_client(client)


class TestValidateGlobals:
    def test_empty_globals_pass(self):
        cve_schema.validate_globals({})

    def test_websocket_port_out_of_range_rejected(self):
        with pytest.raises(ValidationError, match="websocket_probe_ports"):
            cve_schema.validate_globals({"websocket_probe_ports": [99999]})

    def test_dangerous_pattern_missing_pattern_field(self):
        with pytest.raises(ValidationError, match="pattern is required"):
            cve_schema.validate_globals(
                {"dangerous_config_patterns": [{"label": "x"}]}
            )

    def test_non_list_field_rejected(self):
        with pytest.raises(ValidationError, match="must be a list"):
            cve_schema.validate_globals({"remote_probe_paths": "not a list"})
