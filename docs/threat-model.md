# Threat Model

## Assets

- Input files provided by the operator
- Generated reports (JSON, HTML, CSV, SARIF)
- Temporary files during analysis

## Trust boundaries

```
[Operator] --> [Input file] --> [csp-analyzer] --> [Report files]
```

- Input files are **untrusted** (adversarial filenames, oversized content, path traversal attempts).
- The tool **never executes** analyzed binaries.
- **Offline by default.** No network calls unless operator explicitly passes `--allow-network`.

## Attacker capabilities

- Craft files with traversal paths (`../../etc/passwd`)
- Provide oversized files to cause resource exhaustion
- Embed XSS payloads in filenames (mitigated by JSON-island HTML rendering)

## Controls

| Threat | Control |
|--------|---------|
| Path traversal | `safe_resolve_path()` from secintel-core |
| Resource exhaustion | `max_file_bytes` config + `bounded_read_file()` |
| Report XSS | secintel-core JSON-island rendering |
| Binary execution | Never executed — static hash only |

## Assumptions

- Operator runs on systems they own or are authorized to test.
- Python runtime is not compromised.
