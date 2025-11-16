"""CLI entry point and command definitions."""

import json
import logging
import sys
from pathlib import Path

import click

from wawc.core.findings import ScanResult, Severity
from wawc.engine.runner import CHECK_REGISTRY, run_scan
from wawc.pro.license import check_license
from wawc.reporter.console import print_json, print_table
from wawc.reporter.render import generate_html_report, generate_pdf_report

logger = logging.getLogger(__name__)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.version_option(version="1.0.0")
def cli(verbose: bool) -> None:
    """WAWC - Well-Architected Watchdog CLI.

    Scan AWS accounts for common misconfigurations and security issues.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@cli.command()
@click.option(
    "--checks",
    "-c",
    default="s3,sg,rds",
    help="Comma-separated list of checks to run (s3,sg,rds)",
)
@click.option("--profile", "-p", help="AWS profile name")
@click.option("--region", "-r", default="ap-south-1", help="AWS region")
@click.option(
    "--all-regions",
    is_flag=True,
    help="Scan all enabled regions (Pro feature)",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file (for JSON format)",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["HIGH", "MEDIUM", "LOW"]),
    help="Exit with code 2 only for findings at or above this severity",
)
@click.option(
    "--only-high",
    is_flag=True,
    help="Show only HIGH severity findings",
)
def scan(
    checks: str,
    profile: str | None,
    region: str,
    all_regions: bool,
    format: str,
    output: str | None,
    severity_threshold: str | None,
    only_high: bool,
) -> None:
    """Scan AWS account for misconfigurations."""
    # Parse checks
    check_list = [c.strip() for c in checks.split(",")]

    # Validate checks
    invalid = [c for c in check_list if c not in CHECK_REGISTRY]
    if invalid:
        click.echo(f"Error: Invalid checks: {', '.join(invalid)}", err=True)
        click.echo(f"Available checks: {', '.join(CHECK_REGISTRY.keys())}")
        sys.exit(1)

    # Check Pro license for multi-region
    if all_regions and not check_license():
        click.echo("⚠ Multi-region scanning requires a Pro license", err=True)
        sys.exit(1)

    # Determine regions
    regions = [region] if not all_regions else []

    try:
        # Run scan
        click.echo(f"Starting scan with checks: {', '.join(check_list)}")
        result = run_scan(profile, regions, check_list, multi_region=all_regions)

        # Filter findings if needed
        if only_high:
            result.findings = [f for f in result.findings if f.severity == Severity.HIGH]

        # Output results
        if format == "json":
            if output:
                with open(output, "w") as f:
                    print_json(result, f)
                click.echo(f"✓ Results saved to {output}")
            else:
                print_json(result, sys.stdout)
        else:
            severity_filter = Severity.HIGH if only_high else None
            print_table(result, severity_filter)

        # Determine exit code
        exit_code = 0
        if result.findings:
            if severity_threshold:
                threshold = Severity(severity_threshold)
                threshold_order = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
                has_threshold_findings = any(
                    threshold_order[f.severity] >= threshold_order[threshold]
                    for f in result.findings
                )
                if has_threshold_findings:
                    exit_code = 2
            else:
                exit_code = 2

        sys.exit(exit_code)

    except Exception as e:
        logger.exception("Scan failed")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)



@cli.command()
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--out", "-o", required=True, help="Output HTML file path")
@click.option("--pdf", help="Also generate PDF report (Pro feature)")
def report(findings_file: str, out: str, pdf: str | None) -> None:
    """Generate HTML/PDF report from findings JSON file (Pro feature)."""
    try:
        # Load findings
        with open(findings_file) as f:
            data = json.load(f)

        # Reconstruct ScanResult
        result = ScanResult(
            findings=[],
            errors=data.get("errors", []),
            regions_scanned=data.get("summary", {}).get("regions_scanned", []),
            checks_run=data.get("summary", {}).get("checks_run", []),
        )

        # Parse findings
        from wawc.core.findings import Finding

        for finding_data in data.get("findings", []):
            result.findings.append(Finding(**finding_data))

        # Generate HTML report
        generate_html_report(result, out)

        # Generate PDF if requested
        if pdf:
            generate_pdf_report(out, pdf)

    except Exception as e:
        logger.exception("Report generation failed")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def main() -> None:
    """Entry point for console script."""
    cli()


if __name__ == "__main__":
    main()
