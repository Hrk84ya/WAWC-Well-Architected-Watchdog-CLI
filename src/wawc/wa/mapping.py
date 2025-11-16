"""Map findings to AWS Well-Architected Framework pillars."""

from collections import defaultdict

from wawc.core.findings import Finding, ScanResult

# Well-Architected Pillar descriptions
WA_PILLARS = {
    "Security": {
        "description": "Protect information, systems, and assets while delivering business value",
        "focus": "Data protection, privilege management, infrastructure protection",
    },
    "Reliability": {
        "description": "Ensure workloads perform their intended functions correctly and consistently",
        "focus": "Backup and recovery, fault tolerance, high availability",
    },
    "Operational Excellence": {
        "description": "Run and monitor systems to deliver business value",
        "focus": "Operations as code, documentation, frequent small changes",
    },
    "Performance Efficiency": {
        "description": "Use computing resources efficiently to meet requirements",
        "focus": "Resource selection, monitoring, trade-offs",
    },
    "Cost Optimization": {
        "description": "Avoid unnecessary costs and optimize spending",
        "focus": "Cost-effective resources, matching supply with demand",
    },
}


def group_findings_by_pillar(result: ScanResult) -> dict[str, list[Finding]]:
    """Group findings by Well-Architected pillar."""
    pillar_findings: dict[str, list[Finding]] = defaultdict(list)

    for finding in result.findings:
        for pillar in finding.wa_pillars:
            pillar_findings[pillar].append(finding)

    return dict(pillar_findings)


def get_pillar_summary(result: ScanResult) -> dict[str, dict]:
    """Generate summary statistics per pillar."""
    pillar_findings = group_findings_by_pillar(result)
    summary = {}

    for pillar, findings in pillar_findings.items():
        summary[pillar] = {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == "HIGH"),
            "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity == "LOW"),
            "description": WA_PILLARS.get(pillar, {}).get("description", ""),
        }

    return summary
