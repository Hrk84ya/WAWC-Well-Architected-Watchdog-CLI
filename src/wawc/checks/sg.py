"""Security Group checks for overly permissive rules."""

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from wawc.core.findings import Finding, Severity

logger = logging.getLogger(__name__)

# Risky common ports
RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana",
}


def check_security_groups(
    session: boto3.Session, region: str
) -> tuple[list[Finding], list[dict[str, str]]]:
    """
    Check for overly permissive Security Group rules.

    Flags:
    - Rules allowing 0.0.0.0/0 or ::/0
    - All ports open
    - Risky common ports exposed
    """
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []

    try:
        ec2_client = session.client("ec2", region_name=region)

        # Paginate through security groups
        paginator = ec2_client.get_paginator("describe_security_groups")
        page_iterator = paginator.paginate()

        for page in page_iterator:
            security_groups = page.get("SecurityGroups", [])

            for sg in security_groups:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                vpc_id = sg.get("VpcId", "default")

                # Check ingress rules
                for permission in sg.get("IpPermissions", []):
                    from_port = permission.get("FromPort", -1)
                    to_port = permission.get("ToPort", -1)
                    ip_protocol = permission.get("IpProtocol", "-1")

                    # Check IPv4 ranges
                    for ip_range in permission.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            findings.append(
                                _create_sg_finding(
                                    sg_id,
                                    sg_name,
                                    vpc_id,
                                    region,
                                    permission,
                                    cidr,
                                    "IPv4",
                                    from_port,
                                    to_port,
                                    ip_protocol,
                                )
                            )

                    # Check IPv6 ranges
                    for ipv6_range in permission.get("Ipv6Ranges", []):
                        cidr = ipv6_range.get("CidrIpv6", "")
                        if cidr == "::/0":
                            findings.append(
                                _create_sg_finding(
                                    sg_id,
                                    sg_name,
                                    vpc_id,
                                    region,
                                    permission,
                                    cidr,
                                    "IPv6",
                                    from_port,
                                    to_port,
                                    ip_protocol,
                                )
                            )

    except ClientError as e:
        errors.append(
            {"service": "ec2", "resource": "security_groups", "error": str(e)}
        )
        logger.error(f"Error checking security groups in {region}: {e}")

    return findings, errors


def _create_sg_finding(
    sg_id: str,
    sg_name: str,
    vpc_id: str,
    region: str,
    permission: dict[str, Any],
    cidr: str,
    ip_version: str,
    from_port: int,
    to_port: int,
    ip_protocol: str,
) -> Finding:
    """Create a finding for an open security group rule."""
    # Determine severity
    severity = Severity.MEDIUM
    risk_notes = []

    # All ports open
    if ip_protocol == "-1":
        severity = Severity.HIGH
        risk_notes.append("ALL PORTS AND PROTOCOLS")
    # All ports in range
    elif from_port == 0 and to_port == 65535:
        severity = Severity.HIGH
        risk_notes.append("ALL PORTS")
    # Check for risky ports
    else:
        for port in range(from_port, to_port + 1):
            if port in RISKY_PORTS:
                severity = Severity.HIGH
                risk_notes.append(f"{RISKY_PORTS[port]} (port {port})")

    port_desc = (
        "ALL"
        if ip_protocol == "-1"
        else f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
    )
    protocol_desc = "ALL" if ip_protocol == "-1" else ip_protocol.upper()

    title = f"Open Security Group: {sg_id} ({sg_name})"
    description = (
        f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} allows {ip_version} "
        f"traffic from {cidr} on {protocol_desc} protocol, ports {port_desc}."
    )

    if risk_notes:
        description += f" HIGH RISK: {', '.join(risk_notes)}"

    evidence = {
        "security_group_id": sg_id,
        "security_group_name": sg_name,
        "vpc_id": vpc_id,
        "cidr": cidr,
        "ip_version": ip_version,
        "protocol": ip_protocol,
        "from_port": from_port,
        "to_port": to_port,
        "permission": permission,
    }

    remediation = (
        f"1. Review the security group rule allowing {cidr}:\n"
        f"   aws ec2 describe-security-groups --group-ids {sg_id} --region {region}\n"
        f"2. Restrict the CIDR to known IP ranges:\n"
        f"   aws ec2 revoke-security-group-ingress --group-id {sg_id} "
        f"--protocol {ip_protocol} --port {from_port}"
    )

    if from_port != to_port:
        remediation += f"-{to_port}"

    remediation += f" --cidr {cidr}\n"
    remediation += (
        f"3. Add specific CIDR ranges:\n"
        f"   aws ec2 authorize-security-group-ingress --group-id {sg_id} "
        f"--protocol {ip_protocol} --port {from_port}"
    )

    if from_port != to_port:
        remediation += f"-{to_port}"

    remediation += " --cidr <YOUR_CIDR>\n"
    remediation += "4. Consider using AWS Systems Manager Session Manager instead of direct SSH/RDP"

    return Finding(
        id=f"sg-open-{sg_id}-{from_port}-{to_port}-{ip_protocol}",
        service="ec2",
        resource_id=sg_id,
        region=region,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        wa_pillars=["Security"],
        tags={"check": "sg-open-rule", "vpc_id": vpc_id},
    )
