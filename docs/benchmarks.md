# Benchmarks

Measured on the development machine during Phase 0 verification (2026-09-02).

## Environment

- OS: Windows 10 (10.0.26200)
- Python: 3.12.10

## Workloads

| Operation | Input | Time | Memory |
|-----------|-------|------|--------|
| `analyze sample_data/example.txt` | 202 bytes | 0.0757s (first run) | not measured |
| `analyze sample_data/example.txt` (rerun) | 202 bytes | 0.0009s | not measured |
| `analyze` + HTML report | 202 bytes | not measured | not measured |

_Note: First-run time includes module import overhead; steady-state rerun is sub-millisecond._
