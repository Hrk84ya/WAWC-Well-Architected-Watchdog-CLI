"""S3 public bucket checks."""

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from wawc.core.findings import Finding, Severity

logger = logging.getLogger(__name__)


def check_s3_public_buckets(
    session: boto3.Session, region: str
) -> tuple[list[Finding], list[dict[str, str]]]:
    """
    Check for publicly accessible S3 buckets.

    Evaluates:
    - Public Access Block settings
    - Bucket ACLs for AllUsers/AuthenticatedUsers grants
    - Bucket policy public status
    """
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []

    try:
        s3_client = session.client("s3", region_name=region)

        # List all buckets
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                # Check bucket location
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get("LocationConstraint") or "us-east-1"

                # Skip if bucket is in a different region
                if bucket_region != region and region != "us-east-1":
                    continue

                evidence: dict[str, Any] = {"bucket_name": bucket_name}
                is_public = False
                reasons = []

                # Check Public Access Block
                try:
                    pab_response = s3_client.get_public_access_block(Bucket=bucket_name)
                    pab_config = pab_response.get("PublicAccessBlockConfiguration", {})
                    evidence["public_access_block"] = pab_config

                    # If any PAB setting is False, bucket may be public
                    if not all(
                        [
                            pab_config.get("BlockPublicAcls", False),
                            pab_config.get("IgnorePublicAcls", False),
                            pab_config.get("BlockPublicPolicy", False),
                            pab_config.get("RestrictPublicBuckets", False),
                        ]
                    ):
                        reasons.append("Public Access Block not fully enabled")
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                        evidence["public_access_block"] = "Not configured"
                        reasons.append("Public Access Block not configured")
                    else:
                        raise

                # Check bucket ACL
                try:
                    acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                    grants = acl_response.get("Grants", [])
                    evidence["acl_grants"] = grants

                    for grant in grants:
                        grantee = grant.get("Grantee", {})
                        grantee_type = grantee.get("Type")
                        uri = grantee.get("URI", "")

                        if grantee_type == "Group" and (
                            "AllUsers" in uri or "AuthenticatedUsers" in uri
                        ):
                            is_public = True
                            reasons.append(f"ACL grants to {uri.split('/')[-1]}")
                except ClientError as e:
                    logger.debug(f"Could not get ACL for {bucket_name}: {e}")

                # Check bucket policy status
                try:
                    policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                    is_policy_public = policy_status.get("PolicyStatus", {}).get(
                        "IsPublic", False
                    )
                    evidence["policy_public"] = is_policy_public

                    if is_policy_public:
                        is_public = True
                        reasons.append("Bucket policy allows public access")
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                        logger.debug(f"Could not get policy status for {bucket_name}: {e}")

                # Create finding if bucket is public
                if is_public or reasons:
                    evidence["reasons"] = reasons
                    findings.append(
                        Finding(
                            id=f"s3-public-{bucket_name}",
                            service="s3",
                            resource_id=bucket_name,
                            region=bucket_region,
                            severity=Severity.HIGH,
                            title=f"Public S3 Bucket: {bucket_name}",
                            description=f"Bucket '{bucket_name}' is publicly accessible. "
                            f"Reasons: {', '.join(reasons)}",
                            evidence=evidence,
                            remediation=(
                                "1. Enable S3 Block Public Access at account level\n"
                                "2. Enable Block Public Access for this bucket:\n"
                                f"   aws s3api put-public-access-block --bucket {bucket_name} "
                                "--public-access-block-configuration "
                                "BlockPublicAcls=true,IgnorePublicAcls=true,"
                                "BlockPublicPolicy=true,RestrictPublicBuckets=true\n"
                                "3. Review and remove public ACL grants\n"
                                "4. Review bucket policy for public access statements"
                            ),
                            wa_pillars=["Security"],
                            tags={"check": "s3-public-bucket"},
                        )
                    )

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code not in ["NoSuchBucket", "AccessDenied"]:
                    errors.append(
                        {
                            "service": "s3",
                            "resource": bucket_name,
                            "error": str(e),
                        }
                    )
                    logger.warning(f"Error checking bucket {bucket_name}: {e}")

    except ClientError as e:
        errors.append({"service": "s3", "resource": "list_buckets", "error": str(e)})
        logger.error(f"Error listing S3 buckets: {e}")

    return findings, errors
