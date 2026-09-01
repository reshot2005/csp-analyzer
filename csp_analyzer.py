#!/usr/bin/env python3
"""Analyze Content-Security-Policy response headers.

This utility performs a passive, defensive review of a URL's CSP response
header. It identifies common policy weaknesses and reports the affected
directives without attempting to bypass the policy or execute page content.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Iterable


USER_AGENT = "sec-toolkit-csp-analyzer/2.0"

RISK_LEVELS = ("HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class Finding:
    """A single CSP policy observation."""

    severity: str
    directive: str
    issue: str
    recommendation: str


@dataclass(frozen=True)
class CspReport:
    """Structured CSP analysis result."""

    url: str
    final_url: str
    status: int
    header_present: bool
    csp: str | None
    findings: tuple[Finding, ...]


def tokenize_policy(policy: str) -> list[list[str]]:
    """Parse a CSP into directive/source-token lists."""
    directives: list[list[str]] = []

    for raw_directive in policy.split(";"):
        tokens = raw_directive.strip().split()
        if tokens:
            directives.append(tokens)

    return directives


def analyze_csp(policy: str | None) -> tuple[Finding, ...]:
    """Analyze a CSP string and return defensive findings."""
    if not policy or not policy.strip():
        return (
            Finding(
                "MEDIUM",
                "policy",
                "No Content-Security-Policy header is present.",
                "Deploy a CSP appropriate to the application's content and trust model.",
            ),
        )

    findings: list[Finding] = []

    for tokens in tokenize_policy(policy):
        directive = tokens[0].lower()
        sources = {token.lower() for token in tokens[1:]}

        if "'unsafe-inline'" in sources:
            severity = (
                "MEDIUM"
                if directive in {"script-src", "default-src", "style-src"}
                else "LOW"
            )
            findings.append(
                Finding(
                    severity,
                    directive,
                    "'unsafe-inline' weakens CSP restrictions for this directive.",
                    "Prefer nonces or hashes for inline content where practical.",
                )
            )

        if "'unsafe-eval'" in sources:
            findings.append(
                Finding(
                    "MEDIUM",
                    directive,
                    "'unsafe-eval' permits string-to-code evaluation patterns.",
                    "Remove 'unsafe-eval' unless the application has a documented requirement.",
                )
            )

        if "*" in sources:
            severity = "MEDIUM" if directive in {"script-src", "default-src"} else "LOW"
            findings.append(
                Finding(
                    severity,
                    directive,
                    "Wildcard source '*' is allowed for this directive.",
                    "Restrict sources to the smallest set of trusted origins.",
                )
            )

        if "'none'" in sources and len(sources) > 1:
            findings.append(
                Finding(
                    "LOW",
                    directive,
                    "'none' is combined with other sources; browser handling may make the extra sources ineffective.",
                    "Use 'none' by itself when the directive should deny all sources.",
                )
            )

        if directive == "script-src" and "'strict-dynamic'" not in sources:
            # Informational only: many valid CSPs intentionally use allowlists.
            if not any(
                token.startswith("'nonce-")
                or token.startswith("'sha256-")
                or token.startswith("'sha384-")
                or token.startswith("'sha512-")
                for token in sources
            ):
                findings.append(
                    Finding(
                        "INFO",
                        directive,
                        "No nonce/hash or 'strict-dynamic' was observed in script-src.",
                        "Consider nonce/hash-based script authorization for stronger script controls.",
                    )
                )

    directives = {
        tokens[0].lower(): tokens[1:]
        for tokens in tokenize_policy(policy)
    }

    if "object-src" not in directives:
        findings.append(
            Finding(
                "LOW",
                "object-src",
                "object-src is not explicitly defined.",
                "Consider object-src 'none' if legacy plugin content is unnecessary.",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                "LOW",
                "base-uri",
                "base-uri is not explicitly defined.",
                "Consider base-uri 'self' or 'none' when compatible with the application.",
            )
        )

    return tuple(findings)


def fetch_csp(
    url: str,
    *,
    timeout: float = 10.0,
    insecure: bool = False,
) -> tuple[str, int, str | None]:
    """Fetch a URL and return final URL, HTTP status, and CSP header."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        },
        method="GET",
    )

    if insecure:
        context = ssl._create_unverified_context()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )
    else:
        opener = urllib.request.build_opener()

    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return (
            exc.geturl(),
            exc.code,
            exc.headers.get("Content-Security-Policy"),
        )

    with response:
        return (
            response.geturl(),
            response.status,
            response.headers.get("Content-Security-Policy"),
        )


def render_text(report: CspReport) -> str:
    """Render a human-readable CSP report without unnecessary response data."""
    lines = [
        "Content-Security-Policy Analyzer",
        "================================",
        f"Final URL: {report.final_url}",
        f"HTTP status: {report.status}",
        f"CSP header present: {'yes' if report.header_present else 'no'}",
        "",
    ]

    if report.csp:
        lines.append("CSP directives:")
        for tokens in tokenize_policy(report.csp):
            lines.append(f"  - {' '.join(tokens)}")
        lines.append("")

    if not report.findings:
        lines.append("[OK] No findings were identified by the configured checks.")
        return "\n".join(lines)

    lines.append("Findings:")
    for finding in report.findings:
        lines.append(
            f"[{finding.severity}] {finding.directive}: {finding.issue}"
        )
        lines.append(f"    Recommendation: {finding.recommendation}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Passively analyze a Content-Security-Policy response header. "
            "For authorized defensive security testing."
        )
    )
    parser.add_argument("--url", required=True, help="URL to inspect")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification; authorized lab use only",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    if not args.url.lower().startswith(("http://", "https://")):
        parser.error("--url must use http:// or https://")

    try:
        final_url, status, csp = fetch_csp(
            args.url,
            timeout=args.timeout,
            insecure=args.insecure,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"ERROR: request failed: {exc}", file=sys.stderr)
        return 2

    findings = analyze_csp(csp)
    report = CspReport(
        url=args.url,
        final_url=final_url,
        status=status,
        header_present=bool(csp and csp.strip()),
        csp=csp,
        findings=findings,
    )

    if args.output_format == "json":
        print(json.dumps(asdict(report), indent=2))
    else:
        print(render_text(report))

    # HIGH/MEDIUM findings cause a non-zero security-review status.
    return 1 if any(f.severity in {"HIGH", "MEDIUM"} for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
