"""Tests for S3 checks."""

import boto3
import pytest
from botocore.stub import Stubber

from wawc.checks.s3 import check_s3_public_buckets
from wawc.core.findings import Severity


def test_s3_public_bucket_via_acl():
    """Test detection of public bucket via ACL."""
    session = boto3.Session(region_name="us-east-1")
    client = session.client("s3", region_name="us-east-1")

    with Stubber(client) as stubber:
        # Mock list_buckets
        stubber.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "test-bucket", "CreationDate": "2023-01-01"}]},
        )

        # Mock get_bucket_location (us-east-1 returns empty dict)
        stubber.add_response(
            "get_bucket_location",
            {},
            {"Bucket": "test-bucket"},
        )

        # Mock get_public_access_block - not configured
        stubber.add_client_error(
            "get_public_access_block",
            service_error_code="NoSuchPublicAccessBlockConfiguration",
            expected_params={"Bucket": "test-bucket"},
        )

        # Mock get_bucket_acl - public grant
        stubber.add_response(
            "get_bucket_acl",
            {
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    }
                ]
            },
            {"Bucket": "test-bucket"},
        )

        # Mock get_bucket_policy_status
        stubber.add_client_error(
            "get_bucket_policy_status",
            service_error_code="NoSuchBucketPolicy",
            expected_params={"Bucket": "test-bucket"},
        )

        # Monkey patch the session to return our stubbed client
        original_client = session.client

        def mock_client(service, **kwargs):
            if service == "s3":
                return client
            return original_client(service, **kwargs)

        session.client = mock_client

        findings, errors = check_s3_public_buckets(session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "test-bucket" in findings[0].resource_id
        assert "AllUsers" in findings[0].description


def test_s3_no_findings_when_secure():
    """Test no findings for properly secured bucket."""
    session = boto3.Session(region_name="us-east-1")
    client = session.client("s3", region_name="us-east-1")

    with Stubber(client) as stubber:
        # Mock list_buckets
        stubber.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "secure-bucket", "CreationDate": "2023-01-01"}]},
        )

        # Mock get_bucket_location (us-east-1 returns empty dict)
        stubber.add_response(
            "get_bucket_location",
            {},
            {"Bucket": "secure-bucket"},
        )

        # Mock get_public_access_block - fully enabled
        stubber.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            {"Bucket": "secure-bucket"},
        )

        # Mock get_bucket_acl - no public grants
        stubber.add_response(
            "get_bucket_acl",
            {"Grants": [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]},
            {"Bucket": "secure-bucket"},
        )

        # Mock get_bucket_policy_status
        stubber.add_response(
            "get_bucket_policy_status",
            {"PolicyStatus": {"IsPublic": False}},
            {"Bucket": "secure-bucket"},
        )

        original_client = session.client

        def mock_client(service, **kwargs):
            if service == "s3":
                return client
            return original_client(service, **kwargs)

        session.client = mock_client

        findings, errors = check_s3_public_buckets(session, "us-east-1")

        assert len(findings) == 0
