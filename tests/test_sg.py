"""Tests for Security Group checks."""

import boto3
from botocore.stub import Stubber

from wawc.checks.sg import check_security_groups
from wawc.core.findings import Severity


def test_sg_open_to_world():
    """Test detection of security group open to 0.0.0.0/0."""
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2", region_name="us-east-1")

    with Stubber(client) as stubber:
        stubber.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-12345",
                        "GroupName": "test-sg",
                        "VpcId": "vpc-123",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "Ipv6Ranges": [],
                            }
                        ],
                    }
                ]
            },
        )

        original_client = session.client

        def mock_client(service, **kwargs):
            if service == "ec2":
                return client
            return original_client(service, **kwargs)

        session.client = mock_client

        findings, errors = check_security_groups(session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "sg-12345" in findings[0].resource_id
        assert "SSH" in findings[0].description


def test_sg_ipv6_open():
    """Test detection of security group open to ::/0."""
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2", region_name="us-east-1")

    with Stubber(client) as stubber:
        stubber.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-67890",
                        "GroupName": "test-sg-ipv6",
                        "VpcId": "vpc-456",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [],
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                            }
                        ],
                    }
                ]
            },
        )

        original_client = session.client

        def mock_client(service, **kwargs):
            if service == "ec2":
                return client
            return original_client(service, **kwargs)

        session.client = mock_client

        findings, errors = check_security_groups(session, "us-east-1")

        assert len(findings) == 1
        assert "sg-67890" in findings[0].resource_id
        assert "::/0" in findings[0].description
