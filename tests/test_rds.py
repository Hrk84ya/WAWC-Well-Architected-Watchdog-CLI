"""Tests for RDS checks."""

import boto3
from botocore.stub import Stubber

from wawc.checks.rds import check_rds_backups
from wawc.core.findings import Severity


def test_rds_backups_disabled():
    """Test detection of RDS instance with backups disabled."""
    session = boto3.Session(region_name="us-east-1")
    client = session.client("rds", region_name="us-east-1")

    with Stubber(client) as stubber:
        stubber.add_response(
            "describe_db_instances",
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "test-db",
                        "BackupRetentionPeriod": 0,
                        "PreferredBackupWindow": "",
                        "MultiAZ": False,
                        "Engine": "postgres",
                        "DBInstanceClass": "db.t3.micro",
                    }
                ]
            },
        )

        original_client = session.client

        def mock_client(service, **kwargs):
            if service == "rds":
                return client
            return original_client(service, **kwargs)

        session.client = mock_client

        findings, errors = check_rds_backups(session, "us-east-1")

        # Should have findings for: no backup, no backup window, single-AZ
        assert len(findings) >= 1
        backup_finding = next(f for f in findings if "Backups Disabled" in f.title)
        assert backup_finding.severity == Severity.HIGH
        assert "test-db" in backup_finding.resource_id


def test_rds_low_retention():
    """Test detection of RDS instance with low retention period."""
    session = boto3.Session(region_name="us-east-1")
    client = session.client("rds", region_name="us-east-1")

    with Stubber(client) as stubber:
        stubber.add_response(
            "describe_db_instances",
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "test-db-2",
                        "BackupRetentionPeriod": 3,
                        "PreferredBackupWindow": "03:00-04:00",
                        "MultiAZ": True,
                        "Engine": "mysql",
                        "DBInstanceClass": "db.t3.small",
                    }
                ]
            },
        )

        original_client = session.client

        def mock_client(service, **kwargs):
            if service == "rds":
                return client
            return original_client(service, **kwargs)

        session.client = mock_client

        findings, errors = check_rds_backups(session, "us-east-1", min_retention_days=7)

        assert len(findings) >= 1
        retention_finding = next(f for f in findings if "Low Backup Retention" in f.title)
        assert retention_finding.severity == Severity.MEDIUM
