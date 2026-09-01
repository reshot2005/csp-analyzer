import unittest

from csp_analyzer import analyze_csp, tokenize_policy


class TestCSPAnalyzer(unittest.TestCase):
    def test_tokenize_policy(self):
        policy = "default-src 'self'; script-src 'self' https://cdn.example"
        parsed = tokenize_policy(policy)

        self.assertEqual(parsed[0], ["default-src", "'self'"])
        self.assertEqual(
            parsed[1],
            ["script-src", "'self'", "https://cdn.example"],
        )

    def test_unsafe_inline_is_detected(self):
        findings = analyze_csp("script-src 'self' 'unsafe-inline'")
        self.assertTrue(
            any(
                f.directive == "script-src"
                and f.severity == "MEDIUM"
                and "unsafe-inline" in f.issue
                for f in findings
            )
        )

    def test_unsafe_eval_is_detected(self):
        findings = analyze_csp("script-src 'self' 'unsafe-eval'")
        self.assertTrue(any("unsafe-eval" in f.issue for f in findings))

    def test_wildcard_is_detected(self):
        findings = analyze_csp("img-src *")
        self.assertTrue(any(f.directive == "img-src" for f in findings))

    def test_missing_object_src_is_reported(self):
        findings = analyze_csp("default-src 'self'")
        self.assertTrue(any(f.directive == "object-src" for f in findings))

    def test_missing_base_uri_is_reported(self):
        findings = analyze_csp("default-src 'self'")
        self.assertTrue(any(f.directive == "base-uri" for f in findings))

    def test_nonce_based_script_policy_is_not_flagged_for_missing_nonce(self):
        findings = analyze_csp(
            "default-src 'self'; "
            "script-src 'self' 'nonce-abc123'; "
            "object-src 'none'; "
            "base-uri 'none'"
        )

        self.assertFalse(
            any(
                f.directive == "script-src"
                and "No nonce/hash" in f.issue
                for f in findings
            )
        )

    def test_none_combined_with_sources_is_reported(self):
        findings = analyze_csp("img-src 'none' https://cdn.example")
        self.assertTrue(
            any("'none'" in f.issue for f in findings)
        )

    def test_empty_policy_is_reported(self):
        findings = analyze_csp(None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")


if __name__ == "__main__":
    unittest.main()
