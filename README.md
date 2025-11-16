# 🛡️ WAWC - Well-Architected Watchdog CLI

A production-ready Python CLI tool that scans AWS accounts for common misconfigurations and security issues, aligned with the AWS Well-Architected Framework.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

### Free Tier
- ✅ **S3 Security**: Detect public buckets via ACLs, policies, and Public Access Block
- ✅ **Security Groups**: Find overly permissive rules (0.0.0.0/0, ::/0)
- ✅ **RDS Backups**: Check backup retention, windows, and Multi-AZ configuration
- ✅ **Terminal Output**: Rich table formatting with severity highlighting
- ✅ **JSON Export**: Machine-readable output for CI/CD integration
- ✅ **Exit Codes**: Non-zero exit for findings (perfect for pipelines)

### Pro Tier 🔒
- 🌍 **Multi-Region Scanning**: Parallel scans across all enabled regions
- 📊 **HTML Reports**: Beautiful, responsive reports with dark mode
- 📄 **PDF Export**: Generate PDF reports via headless browser
- 🏛️ **WA Pillar Mapping**: Findings mapped to Well-Architected pillars
- 📈 **Severity Summaries**: Executive dashboards and remediation checklists

## Installation

### Using pipx (Recommended)

```bash
pipx install wawc
```

### Using pip

```bash
pip install wawc
```

### From Source

```bash
git clone https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI.git
cd WAWC-Well-Architected-Watchdog-CLI
pip install -e .
```

## Quick Start

### 1. Configure AWS Credentials

```bash
# Using AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=ap-south-1
```

### 2. Run Your First Scan

```bash
# Scan with all checks
wawc scan --checks s3,sg,rds --region ap-south-1

# Scan specific checks only
wawc scan --checks s3 --region us-west-2

# Output as JSON
wawc scan --checks s3,sg,rds --format json > findings.json

# Use specific AWS profile
wawc scan --checks s3 --profile production --region eu-west-1
```

## Usage Examples

### Basic Scanning

```bash
# Scan S3 buckets in ap-south-1
wawc scan --checks s3 --region ap-south-1 --format table

# Scan security groups and RDS
wawc scan --checks sg,rds --region ap-south-1

# Show only HIGH severity findings
wawc scan --checks s3,sg,rds --only-high
```

### CI/CD Integration

```bash
# Exit with code 2 if any findings
wawc scan --checks s3,sg,rds --format json --output findings.json
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  echo "Security findings detected!"
  exit 1
fi

# Exit only for HIGH severity
wawc scan --checks s3,sg,rds --severity-threshold HIGH
```

### Pro Features

```bash
# Multi-region scan (requires Pro license)
export WAWC_LICENSE=WAWC-PRO-YOUR-LICENSE-KEY
wawc scan --all-regions --checks s3,sg,rds --format json > findings.json

# Generate HTML report
wawc report findings.json --out report.html

# Generate PDF report
wawc report findings.json --out report.html --pdf report.pdf
```

## IAM Permissions

WAWC requires read-only permissions. Create an IAM policy using `config/iam-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetPublicAccessBlock",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions",
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach this policy to an IAM user or role used by WAWC.

## Checks Reference

### S3 Public Buckets (`s3`)

Detects publicly accessible S3 buckets by checking:
- Public Access Block configuration (account and bucket level)
- Bucket ACLs for AllUsers/AuthenticatedUsers grants
- Bucket policy public status

**Severity**: HIGH

**Remediation**:
```bash
# Enable Block Public Access
aws s3api put-public-access-block \
  --bucket BUCKET_NAME \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Security Groups (`sg`)

Finds overly permissive security group rules:
- Rules allowing 0.0.0.0/0 (IPv4) or ::/0 (IPv6)
- All ports open
- Risky ports exposed (SSH, RDP, databases)

**Severity**: HIGH (risky ports), MEDIUM (other)

**Remediation**:
```bash
# Revoke overly permissive rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Add specific CIDR
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 22 \
  --cidr 203.0.113.0/24
```

### RDS Backups (`rds`)

Checks RDS backup configuration:
- Automated backups disabled (BackupRetentionPeriod = 0)
- Low retention period (< 7 days)
- Missing preferred backup window
- Single-AZ deployments (informational)

**Severity**: HIGH (no backups), MEDIUM (low retention), LOW (other)

**Remediation**:
```bash
# Enable automated backups
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --backup-retention-period 7 \
  --preferred-backup-window "03:00-04:00"
```

## Output Formats

### Table (Default)

```
Scan Summary
Regions scanned: ap-south-1
Checks run: s3, sg, rds
Total findings: 5

HIGH: 2 | MEDIUM: 2 | LOW: 1

┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Service ┃ Region     ┃ Resource                ┃ Title                                  ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ S3      │ ap-south-1 │ my-public-bucket        │ Public S3 Bucket: my-public-bucket     │
│ HIGH     │ EC2     │ ap-south-1 │ sg-12345                │ Open Security Group: sg-12345          │
└──────────┴─────────┴────────────┴─────────────────────────┴────────────────────────────────────────┘
```

### JSON

```json
{
  "summary": {
    "total_findings": 5,
    "regions_scanned": ["ap-south-1"],
    "checks_run": ["s3", "sg", "rds"],
    "severity_counts": {
      "high": 2,
      "medium": 2,
      "low": 1
    }
  },
  "findings": [
    {
      "id": "s3-public-my-bucket",
      "service": "s3",
      "resource_id": "my-bucket",
      "region": "ap-south-1",
      "severity": "HIGH",
      "title": "Public S3 Bucket: my-bucket",
      "description": "Bucket 'my-bucket' is publicly accessible...",
      "evidence": {...},
      "remediation": "1. Enable S3 Block Public Access...",
      "wa_pillars": ["Security"],
      "tags": {"check": "s3-public-bucket"}
    }
  ]
}
```

## Free vs Pro Comparison

| Feature | Free | Pro |
|---------|------|-----|
| S3 Public Bucket Detection | ✅ | ✅ |
| Security Group Checks | ✅ | ✅ |
| RDS Backup Checks | ✅ | ✅ |
| Single Region Scanning | ✅ | ✅ |
| Terminal Table Output | ✅ | ✅ |
| JSON Export | ✅ | ✅ |
| Multi-Region Scanning | ❌ | ✅ |
| HTML Reports | ❌ | ✅ |
| PDF Export | ❌ | ✅ |
| WA Pillar Mapping | ❌ | ✅ |
| Severity Summaries | ❌ | ✅ |
| Parallel Scanning | ❌ | ✅ |

## Pro License Setup

### Environment Variable

```bash
export WAWC_LICENSE=WAWC-PRO-YOUR-LICENSE-KEY
wawc scan --all-regions
```

### License File (User-level)

```bash
mkdir -p ~/.wawc
echo "WAWC-PRO-YOUR-LICENSE-KEY" > ~/.wawc/license
```

### License File (Project-level)

```bash
echo "WAWC-PRO-YOUR-LICENSE-KEY" > .wawc-license
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

```bash
# Clone and setup
git clone https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI.git
cd WAWC-Well-Architected-Watchdog-CLI
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/

# Type check
mypy src/wawc
```

## Security

WAWC operates in **read-only mode** and never modifies AWS resources. See [SECURITY.md](SECURITY.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.

Pro features require a separate commercial license.

## Support

- 📖 [Documentation](https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI#readme)
- 🐛 [Issue Tracker](https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI/issues)

---

Made with ❤️ by [Hrk84ya](https://github.com/Hrk84ya)
