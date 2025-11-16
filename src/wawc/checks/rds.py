"""RDS backup and configuration checks."""

import logging

import boto3
from botocore.exceptions import ClientError

from wawc.core.findings import Finding, Severity

logger = logging.getLogger(__name__)

DEFAULT_MIN_RETENTION_DAYS = 7


def check_rds_backups(
    session: boto3.Session, region: str, min_retention_days: int = DEFAULT_MIN_RETENTION_DAYS
) -> tuple[list[Finding], list[dict[str, str]]]:
    """
    Check RDS instances for backup misconfigurations.

    Flags:
    - BackupRetentionPeriod == 0 (backups disabled)
    - BackupRetentionPeriod < minimum threshold
    - Missing PreferredBackupWindow
    - Single-AZ deployments (informational)
    """
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []

    try:
        rds_client = session.client("rds", region_name=region)

        # Paginate through DB instances
        paginator = rds_client.get_paginator("describe_db_instances")
        page_iterator = paginator.paginate()

        for page in page_iterator:
            db_instances = page.get("DBInstances", [])

            for db_instance in db_instances:
                db_id = db_instance["DBInstanceIdentifier"]
                retention_period = db_instance.get("BackupRetentionPeriod", 0)
                backup_window = db_instance.get("PreferredBackupWindow", "")
                multi_az = db_instance.get("MultiAZ", False)
                engine = db_instance.get("Engine", "unknown")
                instance_class = db_instance.get("DBInstanceClass", "unknown")

                evidence = {
                    "db_instance_id": db_id,
                    "backup_retention_period": retention_period,
                    "preferred_backup_window": backup_window,
                    "multi_az": multi_az,
                    "engine": engine,
                    "instance_class": instance_class,
                }

                # Check if backups are disabled
                if retention_period == 0:
                    findings.append(
                        Finding(
                            id=f"rds-no-backup-{db_id}",
                            service="rds",
                            resource_id=db_id,
                            region=region,
                            severity=Severity.HIGH,
                            title=f"RDS Backups Disabled: {db_id}",
                            description=(
                                f"RDS instance '{db_id}' has automated backups disabled "
                                f"(BackupRetentionPeriod = 0). This poses a significant risk "
                                f"to data durability and recovery capabilities."
                            ),
                            evidence=evidence,
                            remediation=(
                                f"1. Enable automated backups with appropriate retention:\n"
                                f"   aws rds modify-db-instance --db-instance-identifier {db_id} "
                                f"--backup-retention-period {min_retention_days} "
                                f"--preferred-backup-window 03:00-04:00 --region {region}\n"
                                f"2. Verify backup configuration:\n"
                                f"   aws rds describe-db-instances --db-instance-identifier {db_id}\n"
                                f"3. Consider enabling Multi-AZ for production databases\n"
                                f"4. Test restore procedures regularly"
                            ),
                            wa_pillars=["Reliability", "Operational Excellence"],
                            tags={"check": "rds-backup-disabled", "engine": engine},
                        )
                    )

                # Check if retention period is too low
                elif retention_period < min_retention_days:
                    findings.append(
                        Finding(
                            id=f"rds-low-retention-{db_id}",
                            service="rds",
                            resource_id=db_id,
                            region=region,
                            severity=Severity.MEDIUM,
                            title=f"RDS Low Backup Retention: {db_id}",
                            description=(
                                f"RDS instance '{db_id}' has backup retention period of "
                                f"{retention_period} days, which is below the recommended "
                                f"minimum of {min_retention_days} days."
                            ),
                            evidence=evidence,
                            remediation=(
                                f"1. Increase backup retention period:\n"
                                f"   aws rds modify-db-instance --db-instance-identifier {db_id} "
                                f"--backup-retention-period {min_retention_days} --region {region}\n"
                                f"2. Consider your compliance and recovery requirements\n"
                                f"3. Maximum retention period is 35 days for automated backups"
                            ),
                            wa_pillars=["Reliability", "Operational Excellence"],
                            tags={"check": "rds-low-retention", "engine": engine},
                        )
                    )

                # Check for missing backup window
                if not backup_window and retention_period > 0:
                    findings.append(
                        Finding(
                            id=f"rds-no-backup-window-{db_id}",
                            service="rds",
                            resource_id=db_id,
                            region=region,
                            severity=Severity.LOW,
                            title=f"RDS Missing Backup Window: {db_id}",
                            description=(
                                f"RDS instance '{db_id}' does not have a preferred backup window "
                                f"configured. AWS will choose a random time, which may impact "
                                f"performance during business hours."
                            ),
                            evidence=evidence,
                            remediation=(
                                f"1. Set a preferred backup window during low-traffic hours:\n"
                                f"   aws rds modify-db-instance --db-instance-identifier {db_id} "
                                f"--preferred-backup-window 03:00-04:00 --region {region}\n"
                                f"2. Coordinate with maintenance window if possible"
                            ),
                            wa_pillars=["Operational Excellence"],
                            tags={"check": "rds-no-backup-window", "engine": engine},
                        )
                    )

                # Informational: Single-AZ deployment
                if not multi_az and retention_period > 0:
                    findings.append(
                        Finding(
                            id=f"rds-single-az-{db_id}",
                            service="rds",
                            resource_id=db_id,
                            region=region,
                            severity=Severity.LOW,
                            title=f"RDS Single-AZ Deployment: {db_id}",
                            description=(
                                f"RDS instance '{db_id}' is deployed in a single Availability Zone. "
                                f"For production workloads, consider Multi-AZ deployment for "
                                f"automatic failover and higher availability."
                            ),
                            evidence=evidence,
                            remediation=(
                                f"1. Enable Multi-AZ deployment (requires downtime):\n"
                                f"   aws rds modify-db-instance --db-instance-identifier {db_id} "
                                f"--multi-az --region {region}\n"
                                f"2. Note: This will cause a brief outage during conversion\n"
                                f"3. Multi-AZ provides automatic failover in ~60-120 seconds\n"
                                f"4. Consider cost implications (roughly 2x instance cost)"
                            ),
                            wa_pillars=["Reliability"],
                            tags={"check": "rds-single-az", "engine": engine},
                        )
                    )

    except ClientError as e:
        errors.append({"service": "rds", "resource": "db_instances", "error": str(e)})
        logger.error(f"Error checking RDS instances in {region}: {e}")

    return findings, errors
