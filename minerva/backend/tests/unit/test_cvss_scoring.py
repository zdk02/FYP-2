"""
Unit tests for app.services.cvss.

Covers:
  - score_finding(): CVSS 3.1 derivation from category + confidence
  - enrich(): bulk scoring of finding lists
  - dedupe(): collapses duplicate findings, keeps highest rank
  - risk_grade(): overall A-F grade from severity counts
  - classify_by_category(): groups findings by category
"""

import pytest

from app.services import cvss


pytestmark = pytest.mark.unit


class TestScoreFinding:
    def test_rce_category_is_critical_10(self):
        out = cvss.score_finding({"category": "rce", "confidence": "confirmed"})
        assert out["cvss_score"] == 10.0
        assert out["cvss_severity"] == "critical"
        assert out["cvss_vector"].startswith("CVSS:3.1/")

    def test_command_injection_is_critical(self):
        out = cvss.score_finding({"category": "command_injection", "confidence": "confirmed"})
        assert out["cvss_score"] == 10.0
        assert out["cvss_severity"] == "critical"

    def test_information_disclosure_is_medium(self):
        out = cvss.score_finding({"category": "information_disclosure", "confidence": "high"})
        assert 4.0 <= out["cvss_score"] < 7.0
        assert out["cvss_severity"] == "medium"

    def test_low_confidence_caps_score(self):
        # rce is 10.0 base but low confidence caps at 4.9 (medium)
        out = cvss.score_finding({"category": "rce", "confidence": "low"})
        assert out["cvss_score"] <= 4.9

    def test_medium_confidence_caps_at_6_9(self):
        out = cvss.score_finding({"category": "rce", "confidence": "medium"})
        assert out["cvss_score"] <= 6.9

    def test_unknown_category_falls_back_to_medium(self):
        out = cvss.score_finding({"category": "made_up_category", "confidence": "high"})
        assert out["cvss_score"] == 4.0
        assert out["cvss_severity"] == "medium"

    def test_explicit_cvss_overrides_derived(self):
        out = cvss.score_finding(
            {"category": "rce", "cvss": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L"}
        )
        assert out["cvss_score"] == 7.5
        assert out["cvss_source"] == "explicit"

    def test_derived_source_marked(self):
        out = cvss.score_finding({"category": "ssrf", "confidence": "high"})
        assert out["cvss_source"] == "derived-from-category"

    def test_does_not_mutate_input(self):
        f = {"category": "rce", "confidence": "confirmed"}
        cvss.score_finding(f)
        assert f == {"category": "rce", "confidence": "confirmed"}


class TestEnrich:
    def test_enrich_adds_cvss_fields_to_each_finding(self):
        findings = [
            {"category": "rce", "confidence": "confirmed"},
            {"category": "ssrf", "confidence": "high"},
        ]
        out = cvss.enrich(findings)
        assert len(out) == 2
        assert all("cvss_score" in f for f in out)
        assert all("cvss_vector" in f for f in out)

    def test_enrich_skips_non_dict_entries(self):
        out = cvss.enrich([{"category": "rce"}, "not-a-dict", None])
        assert len(out) == 1


class TestDedupe:
    def test_identical_findings_collapsed(self):
        f = {"category": "rce", "tool": "exec", "parameter": "cmd", "title": "RCE"}
        out = cvss.dedupe([dict(f), dict(f)])
        assert len(out) == 1

    def test_different_categories_kept_separate(self):
        out = cvss.dedupe([
            {"category": "rce", "tool": "a", "parameter": "p", "title": "T"},
            {"category": "ssrf", "tool": "a", "parameter": "p", "title": "T"},
        ])
        assert len(out) == 2

    def test_higher_severity_wins(self):
        a = {"category": "rce", "tool": "x", "parameter": "p", "title": "T",
             "severity": "low", "evidence": [{"e": 1}]}
        b = {"category": "rce", "tool": "x", "parameter": "p", "title": "T",
             "severity": "critical", "evidence": [{"e": 2}]}
        out = cvss.dedupe([a, b])
        assert len(out) == 1
        assert out[0]["severity"] == "critical"
        # Evidence from both should be preserved
        assert len(out[0]["evidence"]) == 2


class TestRiskGrade:
    def test_no_findings_grade_a(self):
        g = cvss.risk_grade([])
        assert g["grade"] == "A"
        assert g["score"] == 0
        assert g["total_findings"] == 0

    def test_one_critical_lands_in_c_or_d(self):
        g = cvss.risk_grade([{"severity": "critical", "confidence": "confirmed"}])
        # 25 (critical) + 5 (confirmed) = 30 → grade C
        assert g["score"] == 30
        assert g["grade"] == "C"

    def test_score_caps_at_100(self):
        many = [{"severity": "critical", "confidence": "confirmed"}] * 20
        g = cvss.risk_grade(many)
        assert g["score"] == 100
        assert g["grade"] == "F"

    def test_severity_counts_populated(self):
        g = cvss.risk_grade([
            {"severity": "high"}, {"severity": "high"}, {"severity": "low"},
        ])
        assert g["severity_counts"]["high"] == 2
        assert g["severity_counts"]["low"] == 1
        assert g["total_findings"] == 3

    def test_grade_boundaries(self):
        # score 9 = A, 10 = B, 24 = B, 25 = C, 49 = C, 50 = D, 74 = D, 75 = F
        assert cvss.risk_grade([{"severity": "high"}] * 0)["grade"] == "A"  # 0
        assert cvss.risk_grade([{"severity": "high"}])["grade"] == "B"      # 10
        assert cvss.risk_grade([{"severity": "critical"}])["grade"] == "C"  # 25
        assert cvss.risk_grade([{"severity": "critical"}] * 2)["grade"] == "D"  # 50
        assert cvss.risk_grade([{"severity": "critical"}] * 3)["grade"] == "F"  # 75


class TestClassifyByCategory:
    def test_groups_by_category(self):
        out = cvss.classify_by_category([
            {"category": "rce", "title": "a"},
            {"category": "rce", "title": "b"},
            {"category": "ssrf", "title": "c"},
        ])
        assert len(out["rce"]) == 2
        assert len(out["ssrf"]) == 1

    def test_missing_category_goes_to_uncategorised(self):
        out = cvss.classify_by_category([{"title": "no-cat"}])
        assert "uncategorised" in out
