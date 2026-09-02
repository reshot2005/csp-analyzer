# Limitations

## Functional

- Only analyzes single files, not directories or recursive trees.
- SHA-256 only — no ssdeep/fuzzy hashing.
- No comparison against known-hash databases (offline tool; operator supplies reference lists separately).

## False positives / false negatives

This tool performs inventory hashing, not detection. It always produces exactly one `OBSERVED` finding per valid input file. There are no detection false positives or false negatives.

| Scenario | Expected behavior | Test |
|----------|-------------------|------|
| Valid file | 1 OBSERVED finding | `tests/positive/test_analyze.py` |
| Empty analysis | 0 findings | `tests/negative/test_empty.py` |
| Missing file | Error, no crash | `tests/malformed/test_malformed.py` |
| Path traversal | Rejected | `tests/malformed/test_malformed.py` |
| Oversized file | Rejected | `tests/malformed/test_malformed.py` |

## Unsupported formats

- Directories (rejected with error)
- Symlinks (rejected by `safe_resolve_path`)
