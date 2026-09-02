# csp-analyzer

**Category:** Template / Demonstration  
**Schema version:** secintel v1.0.0  
**Status:** Template instance — replace with a real tool via `scripts/new_tool.py`

## What problem does this solve?

Establishes a file integrity baseline by computing SHA-256 hashes. This template demonstrates the full collection toolchain: CLI, schema validation, provenance, HTML report, and export formats.

## Why are existing tools insufficient?

| Tool | Gap |
|------|-----|
| `sha256sum` | No provenance, no evidence taxonomy, no report |
| `md5sum` | Weak hash, same gaps |
| VirusTotal | Requires upload (violates offline boundary) |
| Autopsy | Full forensic suite — overkill for a single-file hash |

## What is technically novel?

This is a **template demonstration**, not a novel tool. Its purpose is to prove the `module-template` scaffold works end-to-end. Real tools bootstrapped from this template must document their own novelty in `docs/methodology.md`.

## Evidence and confidence

- Produces exactly one `OBSERVED` finding per input file.
- No confidence score (OBSERVED findings forbid confidence per schema rules).
- Full provenance: tool version, config hash, input SHA-256, timestamps.

## Quick start (5 minutes)

```bash
cd module-template
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ../secintel-core
pip install -e ".[dev]"

# Analyze the sample file
csp-analyzer analyze sample_data/example.txt --json

# Generate HTML report
csp-analyzer analyze sample_data/example.txt --html report.html
```

### Sample output

```json
{
  "schema_version": "1.0.0",
  "findings": [
    {
      "id": "...",
      "title": "File inventory: example.txt",
      "classification": "OBSERVED",
      "evidence": [{"source": "...", "sha256": "...", "excerpt": "..."}],
      "method": "SHA-256 hash of file contents"
    }
  ]
}
```

## Advanced usage

```bash
# Export to multiple formats
csp-analyzer analyze sample_data/example.txt \
  --json --html report.html --csv findings.csv --sarif results.sarif

# Mark as sample data (banner in HTML report)
csp-analyzer analyze sample_data/example.txt --sample --html report.html

# Limit file size
csp-analyzer analyze large.bin --max-bytes 10485760
```

## Reproducibility

Re-run with fixed epoch for deterministic timestamps:

```powershell
$env:SECINTEL_SOURCE_DATE_EPOCH = "1704067200"
csp-analyzer analyze sample_data/example.txt --json
```

Two runs with the same input, config, and tool version produce byte-identical finding IDs and config hashes.

## Bootstrap a new tool

```bash
python scripts/new_tool.py --slug my-tool --name "My Tool" --output ../my-tool
```

## Development

```bash
ruff check src tests
mypy src
pytest
```

## License

MIT
