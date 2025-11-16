# Security Policy

## Read-Only Posture

WAWC is designed with security as a top priority. The tool operates in a **strictly read-only mode** and never modifies AWS resources.

### AWS API Calls

All AWS API calls made by WAWC are read-only operations:

- **S3**: `ListBuckets`, `GetBucketLocation`, `GetBucketAcl`, `GetBucketPolicy`, `GetBucketPolicyStatus`, `GetPublicAccessBlock`
- **EC2**: `DescribeSecurityGroups`, `DescribeRegions`
- **RDS**: `DescribeDBInstances`, `DescribeDBClusters`

### IAM Permissions

The tool requires minimal IAM permissions. See `config/iam-policy.json` for the recommended least-privilege policy.

### Credentials

WAWC uses standard AWS credential chain:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. IAM role (when running on EC2/ECS/Lambda)

**Never hardcode credentials in code or configuration files.**

### Data Handling

- Scan results may contain sensitive information about your AWS infrastructure
- JSON output files should be treated as confidential
- HTML/PDF reports should be stored securely
- Consider encrypting report files at rest

### Reporting Security Issues

If you discover a security vulnerability in WAWC, please report it via [GitHub Security Advisories](https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI/security/advisories/new) with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Please do not open public GitHub issues for security vulnerabilities.

## Best Practices

1. **Use IAM roles** when possible instead of long-lived credentials
2. **Rotate credentials** regularly
3. **Limit scope** using the provided IAM policy
4. **Review findings** before sharing reports
5. **Secure CI/CD** pipelines that run WAWC
6. **Audit access** to systems running WAWC

## Compliance

WAWC helps identify misconfigurations but does not guarantee compliance with any specific framework. Always consult with security and compliance professionals for your specific requirements.
