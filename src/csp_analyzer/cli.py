"""CLI."""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from secintel_core import export_json

from csp_analyzer.core import TOOL_NAME, TOOL_VERSION, AnalysisConfig, analyze_har

app = typer.Typer(
    name=TOOL_NAME,
    help="Parse CSP; flag unsafe-inline/eval, missing directives.",
    no_args_is_help=True,
)
console = Console()


class ExitCode(IntEnum):
    INPUT_ERROR = 2


@app.command()
def analyze(
    har_file: Path = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
    sample: bool = typer.Option(False, "--sample"),
) -> None:
    try:
        result = analyze_har(har_file, config=AnalysisConfig(base_dir=Path.cwd()), is_sample=sample)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INPUT_ERROR) from exc
    table = Table(title="CSP Analysis")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Policies", str(len(result.policies)))
    table.add_row("Weaknesses", str(len(result.weaknesses)))
    console.print(table)
    typer.echo(export_json(result.report))
    raise typer.Exit(code=0)


@app.command()
def version() -> None:
    console.print(f"{TOOL_NAME} v{TOOL_VERSION}")
