"""Tests."""

from pathlib import Path

from csp_analyzer.core import analyze_har
from csp_analyzer.parser import parse_csp, analyze_csp

FIXTURES = Path(__file__).resolve().parent.parent / "sample_data"


class TestCspAnalyzer:
    def test_parses_policies(self) -> None:
        r = analyze_har(FIXTURES / "sample_har_entries.json")
        assert len(r.policies) >= 2

    def test_finds_unsafe_sources(self) -> None:
        r = analyze_har(FIXTURES / "sample_har_entries.json")
        assert any(w.issue == "unsafe_source" for w in r.weaknesses)

    def test_parse_directives(self) -> None:
        p = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")
        issues = analyze_csp(p)
        assert any("unsafe-inline" in i.detail for i in issues)
