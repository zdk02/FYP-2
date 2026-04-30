"""
Unit tests for app.services.evidence — Finding + Evidence builders.

Findings are the structured output of every attack. The shape must be
stable and never lose fields. Evidence builders normalise raw HTTP /
MCP / OOB data into uniform dicts.
"""

import pytest

from app.services import evidence


pytestmark = pytest.mark.unit


class TestEvidenceBuilders:
    def test_ev_mcp_call_extracts_method_and_latency(self):
        resp = {
            "request": {"method": "tools/call"},
            "response": {"result": "ok"},
            "status": 200,
            "latency_ms": 42,
            "transport": "http",
        }
        ev = evidence.ev_mcp_call(resp)
        assert ev["type"] == "mcp_call"
        assert "tools/call" in ev["summary"]
        assert ev["data"]["latency_ms"] == 42
        assert ev["data"]["transport"] == "http"

    def test_ev_http_summary_format(self):
        ev = evidence.ev_http(
            {"method": "POST", "url": "http://x/y"},
            {"status": 201},
        )
        assert ev["type"] == "http_request"
        assert "POST" in ev["summary"]
        assert "201" in ev["summary"]

    def test_ev_oob_hit_includes_token_prefix(self):
        token = "abc123def456ghi"
        ev = evidence.ev_oob_hit(token, [{"ip": "1.1.1.1"}])
        assert ev["type"] == "oob_hit"
        assert ev["data"]["token"] == token
        assert ev["data"]["hits"] == [{"ip": "1.1.1.1"}]
        assert "1 out-of-band callback" in ev["summary"]

    def test_ev_raw_passes_through_summary(self):
        ev = evidence.ev_raw("hello", {"k": "v"})
        assert ev["type"] == "raw"
        assert ev["summary"] == "hello"
        assert ev["data"] == {"k": "v"}

    def test_ev_file_computes_sha256_and_excerpt(self):
        ev = evidence.ev_file("/etc/passwd", "root:x:0:0:")
        assert ev["type"] == "file"
        assert ev["data"]["path"] == "/etc/passwd"
        assert len(ev["data"]["sha256"]) == 64  # sha256 hex
        assert "root" in ev["data"]["excerpt"]

    def test_ev_file_handles_bytes(self):
        ev = evidence.ev_file("/bin/x", b"\x7fELF binary stuff")
        assert ev["type"] == "file"
        assert "ELF" in ev["data"]["excerpt"]


class TestFinding:
    def test_minimal_finding_has_all_required_fields(self):
        f = evidence.Finding(
            attack_id="att-1", title="Test", category="rce",
        ).to_dict()
        for required in ("id", "attack_id", "title", "severity", "confidence",
                         "category", "vulnerable", "target", "evidence",
                         "timestamp"):
            assert required in f, f"missing field: {required}"

    def test_finding_id_is_unique_uuid(self):
        f1 = evidence.Finding(attack_id="a", title="t", category="c").to_dict()
        f2 = evidence.Finding(attack_id="a", title="t", category="c").to_dict()
        assert f1["id"] != f2["id"]
        assert len(f1["id"]) == 32  # uuid4().hex

    def test_invalid_severity_falls_back_to_medium(self):
        f = evidence.Finding(
            attack_id="a", title="t", category="c", severity="apocalyptic"
        ).to_dict()
        assert f["severity"] == "medium"

    def test_invalid_confidence_falls_back_to_medium(self):
        f = evidence.Finding(
            attack_id="a", title="t", category="c", confidence="psychic"
        ).to_dict()
        assert f["confidence"] == "medium"

    def test_severity_normalised_to_lowercase(self):
        f = evidence.Finding(
            attack_id="a", title="t", category="c", severity="CRITICAL"
        ).to_dict()
        assert f["severity"] == "critical"

    def test_add_evidence_appends_to_list(self):
        finding = evidence.Finding(attack_id="a", title="t", category="c")
        finding.add_evidence({"type": "raw", "summary": "x"})
        finding.add_evidence({"type": "raw", "summary": "y"})
        assert len(finding.to_dict()["evidence"]) == 2

    def test_to_dict_returns_a_copy(self):
        finding = evidence.Finding(attack_id="a", title="t", category="c")
        d = finding.to_dict()
        d["title"] = "MUTATED"
        assert finding.to_dict()["title"] == "t"

    def test_full_finding_preserves_all_fields(self):
        f = evidence.Finding(
            attack_id="att-7",
            title="SQL Injection in /search",
            category="sql_injection",
            severity="high",
            confidence="confirmed",
            vulnerable=True,
            target={"host": "127.0.0.1", "port": 8765},
            tool="search_db",
            parameter="q",
            payload="' OR 1=1--",
            description="desc",
            impact="impact",
            remediation="parametrize",
            cwe="CWE-89",
            cve="CVE-2024-0001",
            references=["https://owasp.org/sqli"],
            duration_ms=120,
        ).to_dict()
        assert f["category"] == "sql_injection"
        assert f["cwe"] == "CWE-89"
        assert f["cve"] == "CVE-2024-0001"
        assert f["target"]["port"] == 8765
        assert f["payload"] == "' OR 1=1--"
        assert f["duration_ms"] == 120
