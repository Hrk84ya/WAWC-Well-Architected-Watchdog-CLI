"""Tests for scan runner."""

import boto3
import pytest
from botocore.stub import Stubber

from wawc.engine.runner import run_scan


def test_run_scan_single_region(monkeypatch):
    """Test running scan in single region."""
    session = boto3.Session(region_name="us-east-1")

    # Mock check functions to return empty results
    def mock_check(sess, region):
        return [], []

    monkeypatch.setattr("wawc.engine.runner.check_s3_public_buckets", mock_check)
    monkeypatch.setattr("wawc.engine.runner.check_security_groups", mock_check)
    monkeypatch.setattr("wawc.engine.runner.check_rds_backups", mock_check)

    result = run_scan(None, ["us-east-1"], ["s3", "sg", "rds"], multi_region=False)

    assert result.regions_scanned == ["us-east-1"]
    assert result.checks_run == ["s3", "sg", "rds"]
    assert len(result.findings) == 0


def test_run_scan_invalid_check():
    """Test error handling for invalid check name."""
    with pytest.raises(ValueError, match="Invalid checks"):
        run_scan(None, ["us-east-1"], ["invalid-check"], multi_region=False)
