"""Tests for console reporter."""

import json
from io import StringIO

from wawc.core.findings import Finding, ScanResult, Severity
from wawc.reporter.console import print_json, print_table


def test_print_json():
    """Test JSON output formatting."""
    result = ScanResult(
        findings=[
            Finding(
                id="test-1",
                service="s3",
                resource_id="bucket-1",
                region="us-east-1",
                severity=Severity.HIGH,
                title="Test Finding",
                description="Test description",
                evidence={},
                remediation="Fix it",
                wa_pillars=["Security"],
                tags={},
            )
        ],
        errors=[],
        regions_scanned=["us-east-1"],
        checks_run=["s3"],
    )

    output = StringIO()
    print_json(result, output)
    output.seek(0)

    data = json.load(output)
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["severity_counts"]["high"] == 1
    assert len(data["findings"]) == 1


def test_print_table_no_findings(capsys):
    """Test table output with no findings."""
    result = ScanResult(
        findings=[],
        errors=[],
        regions_scanned=["us-east-1"],
        checks_run=["s3"],
    )

    print_table(result)
    captured = capsys.readouterr()
    assert "No findings detected" in captured.out
