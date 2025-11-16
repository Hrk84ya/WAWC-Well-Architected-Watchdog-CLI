"""Console output formatting with rich tables and JSON."""

import json
from typing import TextIO

from rich.console import Console
from rich.table import Table

from wawc.core.findings import Finding, ScanResult, Severity


def print_table(result: ScanResult, severity_filter: Severity | None = None) -> None:
    """Print findings as a rich table to console."""
    console = Console()

    findings = result.findings
    if severity_filter:
        findings = [f for f in findings if f.severity == severity_filter]

    if not findings:
        console.print("[green]✓ No findings detected![/green]")
        return

    # Summary
    console.print(f"\n[bold]Scan Summary[/bold]")
    console.print(f"Regions scanned: {', '.join(result.regions_scanned)}")
    console.print(f"Checks run: {', '.join(result.checks_run)}")
    console.print(f"Total findings: {len(findings)}\n")

    # Severity breakdown
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)

    console.print(f"[red]HIGH: {high}[/red] | [yellow]MEDIUM: {medium}[/yellow] | [blue]LOW: {low}[/blue]\n")

    # Findings table
    table = Table(title="Security Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=8)
    table.add_column("Service", width=8)
    table.add_column("Region", width=12)
    table.add_column("Resource", width=25)
    table.add_column("Title", width=40)

    for finding in sorted(findings, key=lambda f: (f.severity.value, f.service)):
        severity_color = {
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
        }[finding.severity]

        table.add_row(
            f"[{severity_color}]{finding.severity}[/{severity_color}]",
            finding.service.upper(),
            finding.region,
            finding.resource_id[:25],
            finding.title[:40],
        )

    console.print(table)

    # Errors
    if result.errors:
        console.print(f"\n[yellow]⚠ {len(result.errors)} errors occurred during scan[/yellow]")


def print_json(result: ScanResult, output: TextIO) -> None:
    """Print findings as JSON."""
    data = {
        "summary": {
            "total_findings": len(result.findings),
            "regions_scanned": result.regions_scanned,
            "checks_run": result.checks_run,
            "severity_counts": {
                "high": sum(1 for f in result.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
            },
        },
        "findings": [f.model_dump() for f in result.findings],
        "errors": result.errors,
    }
    json.dump(data, output, indent=2)
