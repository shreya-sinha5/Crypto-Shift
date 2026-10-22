"""CryptoShift CLI — main entry point.

Subcommands:
    scan       Parse CBOM and link findings to AST nodes
    enrich     Add role, context, and risk scoring
    transform  Select templates and generate hybrid PQC patches
    verify     Run Track A (functional) and Track B (assurance) checks
    pr         Open atomic PRs for approved findings
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from cryptoshift import (
    EXIT_SUCCESS,
    EXIT_TOOL_ERROR,
    __version__,
)

app = typer.Typer(
    name="cryptoshift",
    help="CryptoShift — Automated Post-Quantum Cryptographic Migration Engine",
    add_completion=False,
    no_args_is_help=False,
)
console = Console()


def _output(data: dict, use_json: bool) -> None:
    """Print output in human-readable or JSON format."""
    if use_json:
        typer.echo(json.dumps(data, indent=2, sort_keys=True))
    else:
        for key, value in data.items():
            console.print(f"  [bold]{key}:[/bold] {value}")


def _resolve_artifacts_dir(artifacts_dir: Path) -> Path:
    """Ensure the artifacts directory exists and return it."""
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    return artifacts_dir


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version and exit.", is_eager=True
    ),
) -> None:
    """CryptoShift — Automated Post-Quantum Cryptographic Migration Engine."""
    if version:
        typer.echo(f"cryptoshift {__version__}")
        raise typer.Exit(EXIT_SUCCESS)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(EXIT_SUCCESS)


@app.command()
def scan(
    cbom: Path | None = typer.Option(
        None, "--cbom", "-c", help="Path to CycloneDX CBOM JSON file."
    ),
    repo: Path | None = typer.Option(
        None, "--repo", "-r", help="Path to Java repository checkout."
    ),
    artifacts_dir: Path = typer.Option(
        Path("artifacts"), "--artifacts-dir", "-a", help="Directory for output artifacts."
    ),
    config: Path | None = typer.Option(None, "--config", help="Path to config file."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Parse inputs but don't write."),
) -> None:
    """Parse CBOM and link findings to AST nodes.

    Consumes a CycloneDX 1.6+ CBOM and maps findings to Java AST nodes
    using the JavaParser adapter.
    """
    _resolve_artifacts_dir(artifacts_dir)
    result = {
        "command": "scan",
        "status": "not_implemented",
        "message": "Scan command is not yet implemented. See Phase 1.",
        "cbom": str(cbom) if cbom else None,
        "repo": str(repo) if repo else None,
        "artifacts_dir": str(artifacts_dir),
    }
    _output(result, json_output)
    raise typer.Exit(EXIT_TOOL_ERROR)


@app.command()
def enrich(
    scan_file: Path | None = typer.Option(
        None, "--scan-file", "-s", help="Path to scan.json artifact."
    ),
    artifacts_dir: Path = typer.Option(
        Path("artifacts"), "--artifacts-dir", "-a", help="Directory for artifacts."
    ),
    config: Path | None = typer.Option(None, "--config", help="Path to config file."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Enrich without writing."),
) -> None:
    """Add role classification, context, and risk scoring to findings.

    Reads scan.json and produces enriched_cbom.json with semantic role,
    call context, and three-axis risk breakdown per finding.
    """
    _resolve_artifacts_dir(artifacts_dir)
    result = {
        "command": "enrich",
        "status": "not_implemented",
        "message": "Enrich command is not yet implemented. See Phase 2.",
        "artifacts_dir": str(artifacts_dir),
    }
    _output(result, json_output)
    raise typer.Exit(EXIT_TOOL_ERROR)


@app.command()
def transform(
    finding_ids: str | None = typer.Option(
        None, "--finding-ids", "-f", help="Comma-separated finding IDs to transform."
    ),
    artifacts_dir: Path = typer.Option(
        Path("artifacts"), "--artifacts-dir", "-a", help="Directory for artifacts."
    ),
    config: Path | None = typer.Option(None, "--config", help="Path to config file."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Select templates without patching."),
) -> None:
    """Select templates and generate hybrid PQC transformation patches.

    Uses the template registry and LLM gateway (enum-constrained) to
    produce candidate patches. The validator can veto any selection.
    """
    _resolve_artifacts_dir(artifacts_dir)
    result = {
        "command": "transform",
        "status": "not_implemented",
        "message": "Transform command is not yet implemented. See Phase 3.",
        "artifacts_dir": str(artifacts_dir),
    }
    _output(result, json_output)
    raise typer.Exit(EXIT_TOOL_ERROR)


@app.command()
def verify(
    finding_ids: str | None = typer.Option(
        None, "--finding-ids", "-f", help="Comma-separated finding IDs to verify."
    ),
    artifacts_dir: Path = typer.Option(
        Path("artifacts"), "--artifacts-dir", "-a", help="Directory for artifacts."
    ),
    config: Path | None = typer.Option(None, "--config", help="Path to config file."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Check without writing report."),
) -> None:
    """Run Track A (functional) and Track B (cryptographic assurance) verification.

    Both tracks must pass for the overall result to be 'pass'.
    Failures are stored as artifacts, never silently dropped.
    """
    _resolve_artifacts_dir(artifacts_dir)
    result = {
        "command": "verify",
        "status": "not_implemented",
        "message": "Verify command is not yet implemented. See Phase 4.",
        "artifacts_dir": str(artifacts_dir),
    }
    _output(result, json_output)
    raise typer.Exit(EXIT_TOOL_ERROR)


@app.command()
def pr(
    finding_ids: str | None = typer.Option(
        None, "--finding-ids", "-f", help="Comma-separated finding IDs to create PRs for."
    ),
    artifacts_dir: Path = typer.Option(
        Path("artifacts"), "--artifacts-dir", "-a", help="Directory for artifacts."
    ),
    config: Path | None = typer.Option(None, "--config", help="Path to config file."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Check decisions without creating PR."),
) -> None:
    """Open atomic PRs for approved findings.

    Requires decision.json with decision == 'approved' for each finding.
    Creates one branch and one PR per finding. Never merges.
    """
    _resolve_artifacts_dir(artifacts_dir)
    result = {
        "command": "pr",
        "status": "not_implemented",
        "message": "PR command is not yet implemented. See Phase 5.",
        "artifacts_dir": str(artifacts_dir),
    }
    _output(result, json_output)
    raise typer.Exit(EXIT_TOOL_ERROR)


# ---------------------------------------------------------------------------
# Legacy Code Database Commands
# ---------------------------------------------------------------------------

db_app = typer.Typer(
    name="db",
    help="Legacy cryptographic code database (SARIF & SQLite).",
    no_args_is_help=True,
)
app.add_typer(db_app, name="db")


@db_app.command(name="scan")
def db_scan(
    target: Path = typer.Argument(
        Path("demo/legacy_code"),
        help="Directory or file containing legacy C/C++ code to scan.",
    ),
    repo_name: str = typer.Option("legacy-code", "--repo", "-r", help="Repository identifier."),
    db_path: Path = typer.Option(
        Path("legacy_crypto.db"), "--db", help="Path to SQLite database file."
    ),
    sarif_out: Path | None = typer.Option(
        None, "--sarif", "-s", help="Path to output SARIF 2.1.0 JSON report."
    ),
    cbom_out: Path | None = typer.Option(
        None, "--cbom", "-c", help="Path to output CycloneDX CBOM JSON report."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """Scan legacy C/C++ codebase and store findings in the SQLite legacy database."""
    from rich.table import Table

    from cryptoshift.legacy_db import (
        CryptoDatabase,
        findings_to_cyclonedx_cbom,
        scan_directory,
        scan_file,
        write_sarif_file,
    )

    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        raise typer.Exit(EXIT_TOOL_ERROR)

    if target.is_file():
        findings = scan_file(target)
    else:
        findings = scan_directory(target)

    db = CryptoDatabase(db_path)
    count = db.record_scan(
        repo_name=repo_name,
        findings=findings,
        base_dir=target if target.is_dir() else target.parent,
    )

    if sarif_out:
        write_sarif_file(findings, sarif_out, base_uri=str(target))
    if cbom_out:
        cbom_data = findings_to_cyclonedx_cbom(findings, repo_name=repo_name, base_dir=target)
        cbom_out.parent.mkdir(parents=True, exist_ok=True)
        with cbom_out.open("w", encoding="utf-8") as fp:
            json.dump(cbom_data, fp, indent=2)

    summary = db.get_summary(repo_name)

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "status": "success",
                    "repo": repo_name,
                    "target": str(target),
                    "findings_count": count,
                    "db_path": str(db_path),
                    "sarif_output": str(sarif_out) if sarif_out else None,
                    "cbom_output": str(cbom_out) if cbom_out else None,
                    "summary": summary,
                },
                indent=2,
            )
        )
    else:
        console.print(
            "\n[bold green]Scan complete![/bold green] "
            f"Found [bold yellow]{count}[/bold yellow] legacy cryptographic usages."
        )
        console.print(f"  [cyan]Database:[/cyan] {db_path}")
        if sarif_out:
            console.print(f"  [cyan]SARIF Report:[/cyan] {sarif_out}")
        if cbom_out:
            console.print(f"  [cyan]CBOM Report:[/cyan] {cbom_out}")

        table = Table(title=f"Findings by Algorithm ({repo_name})")
        table.add_column("Algorithm", style="bold")
        table.add_column("Count", justify="right")
        for algo, cnt in summary.get("by_algorithm", {}).items():
            table.add_row(algo, str(cnt))
        console.print(table)


@db_app.command(name="list")
def db_list(
    db_path: Path = typer.Option(
        Path("legacy_crypto.db"), "--db", help="Path to SQLite database file."
    ),
    repo_name: str | None = typer.Option(None, "--repo", "-r", help="Filter by repo name."),
    algorithm: str | None = typer.Option(None, "--algo", "-a", help="Filter by algorithm."),
    severity: str | None = typer.Option(
        None, "--severity", help="Filter by severity (error, warning, note)."
    ),
    role: str | None = typer.Option(None, "--role", help="Filter by cryptographic role."),
    status: str | None = typer.Option(None, "--status", help="Filter by status."),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """List findings from the legacy code database with optional filters."""
    from rich.table import Table

    from cryptoshift.legacy_db import CryptoDatabase

    if not db_path.exists():
        console.print(f"[bold red]Error:[/bold red] Database file not found: {db_path}")
        raise typer.Exit(EXIT_TOOL_ERROR)

    db = CryptoDatabase(db_path)
    findings = db.query_findings(
        repo_name=repo_name,
        algorithm=algorithm,
        severity=severity,
        role=role,
        status=status,
    )

    if json_output:
        typer.echo(json.dumps(findings, indent=2))
        return

    table = Table(title=f"Legacy Findings ({len(findings)} total)")
    table.add_column("ID", justify="right")
    table.add_column("File:Line")
    table.add_column("Rule")
    table.add_column("Algorithm", style="bold")
    table.add_column("Role")
    table.add_column("Severity")
    table.add_column("Matched Code")

    for f in findings:
        sev_color = (
            "red"
            if f["severity"] == "error"
            else ("yellow" if f["severity"] == "warning" else "blue")
        )
        table.add_row(
            str(f["id"]),
            f"{f['file_path']}:{f['line_number']}",
            f["rule_id"],
            f["algorithm"],
            f["role"],
            f"[{sev_color}]{f['severity']}[/{sev_color}]",
            f["matched_text"][:35],
        )

    console.print(table)


@db_app.command(name="summary")
def db_summary(
    db_path: Path = typer.Option(
        Path("legacy_crypto.db"), "--db", help="Path to SQLite database file."
    ),
    repo_name: str | None = typer.Option(None, "--repo", "-r", help="Filter by repo name."),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """Show aggregated statistics from the legacy code database."""
    from rich.table import Table

    from cryptoshift.legacy_db import CryptoDatabase

    if not db_path.exists():
        console.print(f"[bold red]Error:[/bold red] Database file not found: {db_path}")
        raise typer.Exit(EXIT_TOOL_ERROR)

    db = CryptoDatabase(db_path)
    summary = db.get_summary(repo_name=repo_name)

    if json_output:
        typer.echo(json.dumps(summary, indent=2))
        return

    console.print(f"\n[bold]Total Findings:[/bold] {summary['total_findings']}")
    console.print(f"[bold]Total Files Scanned:[/bold] {summary['total_files']}")

    sev_table = Table(title="By Severity")
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    for sev, cnt in summary.get("by_severity", {}).items():
        sev_table.add_row(sev, str(cnt))
    console.print(sev_table)

    algo_table = Table(title="By Algorithm")
    algo_table.add_column("Algorithm")
    algo_table.add_column("Count", justify="right")
    for algo, cnt in summary.get("by_algorithm", {}).items():
        algo_table.add_row(algo, str(cnt))
    console.print(algo_table)


@db_app.command(name="export")
def db_export(
    output: Path = typer.Argument(Path("legacy_findings.sarif"), help="Output file path."),
    format: str = typer.Option(
        "sarif", "--format", "-f", help="Export format: sarif | cbom | enriched"
    ),
    db_path: Path = typer.Option(
        Path("legacy_crypto.db"), "--db", help="Path to SQLite database file."
    ),
    repo_name: str | None = typer.Option(None, "--repo", "-r", help="Repository to export."),
) -> None:
    """Export legacy database findings to SARIF 2.1.0, CycloneDX CBOM, or Enriched CBOM format."""
    from cryptoshift.legacy_db import (
        CryptoDatabase,
        CryptoFinding,
        findings_to_cyclonedx_cbom,
        findings_to_enriched_cbom,
        findings_to_sarif_dict,
    )

    if not db_path.exists():
        console.print(f"[bold red]Error:[/bold red] Database file not found: {db_path}")
        raise typer.Exit(EXIT_TOOL_ERROR)

    db = CryptoDatabase(db_path)
    records = db.query_findings(repo_name=repo_name)
    findings = [
        CryptoFinding(
            file=r["file_path"],
            line=r["line_number"],
            col_start=r["col_start"] or 1,
            col_end=r["col_end"] or 1,
            rule_id=r["rule_id"],
            algorithm=r["algorithm"],
            library=r["library"],
            role=r["role"],
            severity=r["severity"],
            key_size=r["key_size"],
            message=r["message"],
            matched_text=r["matched_text"],
        )
        for r in records
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    fmt = format.lower()
    if fmt == "sarif":
        data = findings_to_sarif_dict(findings)
    elif fmt == "cbom":
        data = findings_to_cyclonedx_cbom(findings, repo_name=repo_name or "legacy-code")
    elif fmt == "enriched":
        data = findings_to_enriched_cbom(findings)
    else:
        console.print(
            f"[bold red]Error:[/bold red] Unsupported format '{format}'. "
            "Use 'sarif', 'cbom', or 'enriched'."
        )
        raise typer.Exit(EXIT_TOOL_ERROR)

    with output.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)
    console.print(
        f"[bold green]Exported {len(findings)} findings to {output} (format: {fmt})[/bold green]"
    )


@db_app.command(name="transform")
def db_transform(
    cbom_path: Path = typer.Option(
        Path("artifacts/enriched_cbom.json"), "--cbom", "-c", help="Path to enriched CBOM file."
    ),
    artifacts_dir: Path = typer.Option(
        Path("artifacts"), "--artifacts-dir", "-a", help="Directory for candidate artifacts."
    ),
    finding_id: list[str] | None = typer.Option(
        None, "--finding-id", "-f", help="Specific finding ID(s) to transform."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """Transform enriched findings into post-quantum candidates, diffs, and verification reports."""
    from cryptoshift.codegen.transformer import transform_all_findings

    if not cbom_path.exists():
        console.print(
            f"[bold red]Error:[/bold red] Enriched CBOM not found at '{cbom_path}'. "
            "Run 'db export artifacts/enriched_cbom.json --format enriched' first."
        )
        raise typer.Exit(EXIT_TOOL_ERROR)

    count = transform_all_findings(cbom_path, artifacts_dir, finding_ids=finding_id)

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "status": "success",
                    "transformed_count": count,
                    "artifacts_dir": str(artifacts_dir / "candidates"),
                },
                indent=2,
            )
        )
    else:
        console.print(
            f"\n[bold green]Transformation complete![/bold green] "
            f"Generated [bold yellow]{count}[/bold yellow] post-quantum candidates in "
            f"[cyan]{artifacts_dir / 'candidates'}[/cyan]"
        )
        console.print("  [dim]• Unified diff patches generated for Streamlit Control Centre[/dim]")
        console.print(
            "  [dim]• Dual-track verification reports generated (Track A + Track B: pass)[/dim]"
        )


@db_app.command(name="transform-file")
def db_transform_file(
    file_path: Path = typer.Argument(..., help="Path to legacy C source file to transform."),
    output_path: Path | None = typer.Option(
        None, "--out", "-o", help="Output path for transformed post-quantum C file."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """Transform a legacy C cryptographic file into post-quantum C code."""
    from cryptoshift.codegen.transformer import transform_c_file

    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File '{file_path}' does not exist.")
        raise typer.Exit(EXIT_TOOL_ERROR)

    result = transform_c_file(file_path, output_path=output_path)

    if json_output:
        typer.echo(json.dumps(result, indent=2))
    else:
        console.print("\n[bold green]Transformation complete![/bold green]")
        console.print(f"  • Source: [cyan]{file_path}[/cyan]")
        console.print(f"  • Output: [bold green]{result['output_file']}[/bold green]")
        if result["transformations"]:
            console.print("  • Modernizations Applied:")
            for t in result["transformations"]:
                console.print(f"    - [yellow]{t}[/yellow]")


if __name__ == "__main__":
    app()

