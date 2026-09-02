"""Content-Security-Policy parsing and weakness detection."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from secintel_core.security import bounded_read_file

_UNSAFE_SOURCES = ("'unsafe-inline'", "'unsafe-eval'", "data:", "blob:", "*")
_RECOMMENDED_DIRECTIVES = ("default-src", "script-src", "object-src", "base-uri", "frame-ancestors")


@dataclass(frozen=True)
class CspDirective:
    name: str
    sources: tuple[str, ...]


@dataclass(frozen=True)
class ParsedCsp:
    entry_index: int
    url: str
    raw: str
    directives: tuple[CspDirective, ...]


@dataclass(frozen=True)
class CspWeakness:
    entry_index: int
    url: str
    issue: str
    severity: str
    confidence_score: float
    detail: str


@dataclass
class CspCapture:
    entries: list[tuple[int, str, str]] = field(default_factory=list)


def load_csp_headers(path: Path) -> CspCapture:
    data = json.loads(bounded_read_file(path, max_bytes=50 * 1024 * 1024))
    entries_raw = data if isinstance(data, list) else data.get("log", {}).get("entries", [])
    capture = CspCapture()
    for i, entry in enumerate(entries_raw):
        req = entry.get("request", {})
        url = req.get("url", "")
        for h in entry.get("response", {}).get("headers", []):
            if h.get("name", "").lower() == "content-security-policy":
                capture.entries.append((i, url, h["value"]))
    return capture


def parse_csp(raw: str, *, entry_index: int = 0, url: str = "") -> ParsedCsp:
    directives: list[CspDirective] = []
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = re.split(r"\s+", part, maxsplit=1)
        name = tokens[0].lower()
        sources = tuple(tokens[1].split()) if len(tokens) > 1 else ()
        directives.append(CspDirective(name=name, sources=sources))
    return ParsedCsp(entry_index=entry_index, url=url, raw=raw, directives=tuple(directives))


def analyze_csp(parsed: ParsedCsp) -> list[CspWeakness]:
    weaknesses: list[CspWeakness] = []
    directive_names = {d.name for d in parsed.directives}
    for rec in _RECOMMENDED_DIRECTIVES:
        if rec not in directive_names:
            weaknesses.append(
                CspWeakness(
                    entry_index=parsed.entry_index,
                    url=parsed.url,
                    issue="missing_directive",
                    severity="medium" if rec in {"default-src", "script-src"} else "low",
                    confidence_score=0.85,
                    detail=f"Missing {rec} directive",
                )
            )
    for directive in parsed.directives:
        for src in directive.sources:
            if src in _UNSAFE_SOURCES or src == "*":
                weaknesses.append(
                    CspWeakness(
                        entry_index=parsed.entry_index,
                        url=parsed.url,
                        issue="unsafe_source",
                        severity="high" if src in {"'unsafe-inline'", "'unsafe-eval'", "*"} else "medium",
                        confidence_score=0.90,
                        detail=f"{directive.name} allows {src}",
                    )
                )
    return weaknesses
