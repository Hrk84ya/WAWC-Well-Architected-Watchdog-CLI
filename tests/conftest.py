"""Pytest configuration and fixtures."""

import boto3
import pytest
from botocore.stub import Stubber


@pytest.fixture
def aws_session():
    """Create a mock AWS session."""
    return boto3.Session(region_name="us-east-1")


@pytest.fixture
def s3_stubber(aws_session):
    """Create S3 client stubber."""
    client = aws_session.client("s3", region_name="us-east-1")
    with Stubber(client) as stubber:
        yield stubber, client


@pytest.fixture
def ec2_stubber(aws_session):
    """Create EC2 client stubber."""
    client = aws_session.client("ec2", region_name="us-east-1")
    with Stubber(client) as stubber:
        yield stubber, client


@pytest.fixture
def rds_stubber(aws_session):
    """Create RDS client stubber."""
    client = aws_session.client("rds", region_name="us-east-1")
    with Stubber(client) as stubber:
        yield stubber, client
