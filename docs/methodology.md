# Methodology

## Problem

<!-- Describe the real problem this tool solves -->

This template ships `csp-analyzer` as a working demonstration: it hashes an input file and emits one honest `OBSERVED` finding with full provenance. Replace this section when bootstrapping a real tool.

## Adjacent tools

<!-- Originality Gate: list ≥5 existing tools, what they do well, their limitations, and the workflow gap -->

| Tool | Strength | Limitation | Gap |
|------|----------|------------|-----|
| _Tool 1_ | | | |
| _Tool 2_ | | | |
| _Tool 3_ | | | |
| _Tool 4_ | | | |
| _Tool 5_ | | | |

## Differentiation Statement

<!-- One paragraph: why this repo deserves to exist independently rather than being a thin wrapper -->

_Replace this placeholder when creating a real tool._

## Analysis heuristics

<!-- For each detection heuristic: hypothesis, signals, expected behavior, failure modes, validation -->

### file-inventory-sha256

- **Hypothesis:** Computing SHA-256 of a file provides an integrity baseline.
- **Signals:** Raw file bytes.
- **Expected behavior:** Always produces exactly one `OBSERVED` finding per input file.
- **Failure modes:** File unreadable, exceeds size limit, path traversal attempt.
- **Validation:** `tests/positive/test_analyze.py`, `tests/malformed/test_malformed.py`
