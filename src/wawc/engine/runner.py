"""Scan orchestration and execution engine."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import boto3

from wawc.checks.rds import check_rds_backups
from wawc.checks.s3 import check_s3_public_buckets
from wawc.checks.sg import check_security_groups
from wawc.core.findings import Finding, ScanResult

logger = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    "s3": check_s3_public_buckets,
    "sg": check_security_groups,
    "rds": check_rds_backups,
}


def run_scan(
    profile: str | None,
    regions: list[str],
    checks: list[str],
    multi_region: bool = False,
) -> ScanResult:
    """
    Execute security checks across specified regions.

    Args:
        profile: AWS profile name
        regions: List of regions to scan
        checks: List of check names to run
        multi_region: Enable multi-region scanning (Pro feature)

    Returns:
        ScanResult with findings and errors
    """
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    # Validate checks
    invalid_checks = [c for c in checks if c not in CHECK_REGISTRY]
    if invalid_checks:
        raise ValueError(f"Invalid checks: {', '.join(invalid_checks)}")

    # If multi-region is enabled, get all enabled regions
    if multi_region:
        regions = _get_enabled_regions(session)
        logger.info(f"Multi-region scan enabled: {len(regions)} regions")

    all_findings: list[Finding] = []
    all_errors: list[dict[str, str]] = []

    # Run checks per region
    if len(regions) > 1 and multi_region:
        # Parallel execution for multi-region
        with ThreadPoolExecutor(max_workers=min(len(regions), 10)) as executor:
            futures = {
                executor.submit(_scan_region, session, region, checks): region
                for region in regions
            }

            for future in as_completed(futures):
                region = futures[future]
                try:
                    findings, errors = future.result()
                    all_findings.extend(findings)
                    all_errors.extend(errors)
                    logger.info(f"Completed scan for {region}: {len(findings)} findings")
                except Exception as e:
                    logger.error(f"Error scanning region {region}: {e}")
                    all_errors.append(
                        {"service": "runner", "resource": region, "error": str(e)}
                    )
    else:
        # Sequential execution for single region
        for region in regions:
            try:
                findings, errors = _scan_region(session, region, checks)
                all_findings.extend(findings)
                all_errors.extend(errors)
                logger.info(f"Completed scan for {region}: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Error scanning region {region}: {e}")
                all_errors.append({"service": "runner", "resource": region, "error": str(e)})

    return ScanResult(
        findings=all_findings,
        errors=all_errors,
        regions_scanned=regions,
        checks_run=checks,
    )


def _scan_region(
    session: boto3.Session, region: str, checks: list[str]
) -> tuple[list[Finding], list[dict[str, str]]]:
    """Execute checks for a single region."""
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []

    for check_name in checks:
        check_func = CHECK_REGISTRY[check_name]
        try:
            check_findings, check_errors = check_func(session, region)
            findings.extend(check_findings)
            errors.extend(check_errors)
        except Exception as e:
            logger.error(f"Error running check {check_name} in {region}: {e}")
            errors.append(
                {"service": check_name, "resource": region, "error": str(e)}
            )

    return findings, errors


def _get_enabled_regions(session: boto3.Session) -> list[str]:
    """Get list of enabled AWS regions."""
    try:
        ec2_client = session.client("ec2", region_name="us-east-1")
        response = ec2_client.describe_regions(AllRegions=False)
        regions = [r["RegionName"] for r in response["Regions"]]
        return sorted(regions)
    except Exception as e:
        logger.warning(f"Could not fetch enabled regions: {e}. Using default list.")
        return ["us-east-1"]
