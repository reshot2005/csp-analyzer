"""Core CSP analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    InputArtifact,
    Provenance,
    Report,
    Severity,
    build_environment_info,
    canonical_config_hash,
    deterministic_finding_id,
    reproducible_now,
    sha256_file,
)
from secintel_core.security import safe_resolve_path

from csp_analyzer.parser import (
    CspCapture,
    CspWeakness,
    ParsedCsp,
    analyze_csp,
    load_csp_headers,
    parse_csp,
)

TOOL_NAME = "csp-analyzer"
TOOL_VERSION = "0.1.0"
_SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 50 * 1024 * 1024


@dataclass
class AnalysisResult:
    report: Report
    policies: list[ParsedCsp]
    weaknesses: list[CspWeakness]


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_har(
    input_path: Path | str,
    *,
    config: AnalysisConfig | None = None,
    is_sample: bool = False,
) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    resolved = _resolve(cfg.base_dir, input_path)
    if not resolved.is_file():
        raise ValueError(f"HAR file not found: {resolved}")

    input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
    started = reproducible_now()
    capture: CspCapture = load_csp_headers(resolved)
    policies = [parse_csp(raw, entry_index=idx, url=url) for idx, url, raw in capture.entries]
    weaknesses: list[CspWeakness] = []
    for policy in policies:
        weaknesses.extend(analyze_csp(policy))
    findings = _emit_findings(
        policies, weaknesses, input_hash=input_hash, source=str(resolved), started=started
    )

    ended = reproducible_now()
    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash({}),
            inputs=[
                InputArtifact(
                    path=str(resolved), sha256=input_hash, size_bytes=resolved.stat().st_size
                )
            ],
            analysis_started_at=started,
            analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings,
        is_sample_data=is_sample,
        metadata={"policy_count": len(policies), "weakness_count": len(weaknesses)},
    )
    return AnalysisResult(report=report, policies=policies, weaknesses=weaknesses)


def _emit_findings(
    policies: list[ParsedCsp],
    weaknesses: list[CspWeakness],
    *,
    input_hash: str,
    source: str,
    started: Any,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.append(
        Finding(
            id=deterministic_finding_id("csp-policies-observed", input_hash, {"n": len(policies)}),
            title=f"CSP policies parsed: {len(policies)}",
            classification=Classification.OBSERVED,
            evidence=[
                Evidence(source=source, locator={"count": len(policies)}, retrieved_at=started)
            ],
            method="Content-Security-Policy header parsing",
            why_it_matters="CSP policy inventory.",
            plain_language=f"Parsed {len(policies)} CSP headers.",
            severity=Severity.INFO,
            tags=["csp"],
            timestamp=started,
        )
    )
    for w in weaknesses:
        findings.append(
            Finding(
                id=deterministic_finding_id(
                    "csp-weakness", input_hash, {"issue": w.issue, "url": w.url, "detail": w.detail}
                ),
                title=f"CSP weakness: {w.detail}",
                classification=Classification.INFERRED,
                confidence=Confidence(
                    score=w.confidence_score,
                    rationale=w.detail,
                    supporting_indicators=[w.issue],
                ),
                evidence=[
                    Evidence(
                        source=source,
                        locator={"url": w.url, "issue": w.issue},
                        retrieved_at=started,
                    )
                ],
                method="CSP directive analysis",
                why_it_matters="Weak CSP allows XSS and data injection.",
                plain_language=f"{w.detail} at {w.url}.",
                severity=_SEV.get(w.severity, Severity.MEDIUM),
                tags=["csp", w.issue],
                timestamp=started,
            )
        )
    return findings
