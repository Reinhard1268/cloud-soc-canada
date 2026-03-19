# AWS CIS Foundations Benchmark — Lab Results
## CIS AWS Foundations Benchmark v1.4.0 | ca-central-1

**Assessment Date:** 2024-01
**Account:** SOC Lab (Free Tier)
**Assessor:** Automated via Security Hub + cis-benchmark-checker.py
**Overall Score:** Run `python3 aws/security-hub/cis-benchmark-checker.py` for live results

---

## Section 1: Identity and Access Management

| Control | Description | Expected Status | Priority |
|---------|------------|-----------------|---------|
| 1.1 | Maintain current contact details | PASS | Low |
| 1.2 | Ensure security contact information is registered | PASS | Low |
| 1.3 | Ensure security questions are registered | N/A | Low |
| 1.4 | Ensure no root account access key exists | PASS | Critical |
| 1.5 | Ensure MFA is enabled for the root account | PASS | Critical |
| 1.6 | Ensure hardware MFA is enabled for root | MANUAL | High |
| 1.7 | Eliminate use of root account | PASS | High |
| 1.8 | Ensure IAM password policy requires minimum 14 chars | CONFIGURE | Medium |
| 1.9 | Ensure IAM password policy prevents password reuse | CONFIGURE | Medium |
| 1.10 | Ensure MFA is enabled for all IAM users with console access | CONFIGURE | High |
| 1.11 | Do not setup access keys during initial user setup | PASS | Medium |
| 1.12 | Ensure credentials unused for 90+ days are disabled | CONFIGURE | Medium |
| 1.13 | Ensure only one active access key exists per IAM user | CONFIGURE | Low |
| 1.14 | Ensure access keys are rotated every 90 days | CONFIGURE | Medium |
| 1.15 | Ensure IAM users receive permissions only through groups | CONFIGURE | Medium |
| 1.16 | Ensure IAM policies attached only to groups or roles | CONFIGURE | Medium |
| 1.17 | Ensure a support role exists | CONFIGURE | Low |
| 1.18 | Ensure IAM instance roles are used for AWS resource access | CONFIGURE | Medium |
| 1.19 | Ensure expired SSL/TLS certificates are removed | PASS | Medium |
| 1.20 | Ensure IAM Access Analyzer is enabled | CONFIGURE | Medium |
| 1.21 | Ensure IAM users are managed centrally | MANUAL | Low |
| 1.22 | Ensure access to AWSCloudShellFullAccess is restricted | CONFIGURE | Low |

---

## Section 2: Storage

| Control | Description | Expected Status | Priority |
|---------|------------|-----------------|---------|
| 2.1.1 | Ensure S3 bucket policy is set to deny HTTP requests | CONFIGURE | High |
| 2.1.2 | Ensure MFA delete is enabled on S3 buckets | CONFIGURE | Medium |
| 2.1.3 | Ensure all data in Amazon S3 has been discovered/classified | MANUAL | Medium |
| 2.2.1 | Ensure EBS volume encryption is enabled | CONFIGURE | Medium |
| 2.3.1 | Ensure RDS encryption is enabled | CONFIGURE | Medium |

---

## Section 3: Logging

| Control | Description | Expected Status | Priority |
|---------|------------|-----------------|---------|
| 3.1 | Ensure CloudTrail is enabled in all regions | PASS | Critical |
| 3.2 | Ensure CloudTrail log file validation is enabled | PASS | High |
| 3.3 | Ensure AWS Config is enabled | CONFIGURE | Medium |
| 3.4 | Ensure CloudTrail trails are integrated with CloudWatch Logs | PASS | High |
| 3.5 | Ensure AWS Config is enabled in all regions | CONFIGURE | Medium |
| 3.6 | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket | CONFIGURE | Medium |
| 3.7 | Ensure CloudTrail logs are encrypted at rest using KMS | CONFIGURE | Medium |
| 3.8 | Ensure rotation for customer created CMKs is enabled | CONFIGURE | Medium |
| 3.9 | Ensure VPC flow logging is enabled in all VPCs | CONFIGURE | Medium |
| 3.10 | Ensure that Object-level logging for write events is enabled for S3 bucket | PASS | Medium |
| 3.11 | Ensure that Object-level logging for read events is enabled for S3 bucket | PASS | Medium |

---

## Section 4: Monitoring

| Control | Description | Expected Status | Priority |
|---------|------------|-----------------|---------|
| 4.1 | Unauthorized API calls alarm | CONFIGURE | High |
| 4.2 | Management Console sign-in without MFA alarm | CONFIGURE | High |
| 4.3 | Root account usage alarm | CONFIGURE | Critical |
| 4.4 | IAM policy changes alarm | CONFIGURE | High |
| 4.5 | CloudTrail configuration changes alarm | CONFIGURE | High |
| 4.6 | AWS Management Console authentication failures alarm | CONFIGURE | Medium |
| 4.7 | Disabling or scheduled deletion of customer KMS keys alarm | CONFIGURE | Medium |
| 4.8 | S3 bucket policy changes alarm | CONFIGURE | Medium |
| 4.9 | AWS Config configuration changes alarm | CONFIGURE | Medium |
| 4.10 | Security group changes alarm | CONFIGURE | Medium |
| 4.11 | Network Access Control List changes alarm | CONFIGURE | Medium |
| 4.12 | Changes to network gateways alarm | CONFIGURE | Medium |
| 4.13 | Route table changes alarm | CONFIGURE | Medium |
| 4.14 | VPC changes alarm | CONFIGURE | Medium |
| 4.15 | AWS Organizations changes alarm | CONFIGURE | Medium |

---

## Section 5: Networking

| Control | Description | Expected Status | Priority |
|---------|------------|-----------------|---------|
| 5.1 | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote administration ports | CONFIGURE | High |
| 5.2 | Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports | CONFIGURE | High |
| 5.3 | Ensure VPC flow logging is enabled in all VPCs | CONFIGURE | Medium |
| 5.4 | Ensure default security group restricts all traffic | CONFIGURE | Medium |
| 5.5 | Ensure routing tables for VPC peering are least access | CONFIGURE | Medium |

---

## Quick Remediation Commands

### Enable MFA for IAM users
```bash
# List users without MFA
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} bash -c 'mfa=$(aws iam list-mfa-devices --user-name {} --query "MFADevices" --output text); [ -z "$mfa" ] && echo "NO MFA: {}"'
```

### Set strong password policy
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24
```

### Enable IAM Access Analyzer
```bash
aws accessanalyzer create-analyzer \
  --analyzer-name soc-lab-analyzer \
  --type ACCOUNT \
  --region ca-central-1
```

### Create CloudWatch alarms for CIS Section 4
```bash
# Root account usage alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-4.3-RootAccountUsage" \
  --alarm-description "Alarm for root account usage" \
  --metric-name "RootAccountUsage" \
  --namespace "CloudTrailMetrics" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions YOUR_SNS_ARN \
  --region ca-central-1
```

---

## Scoring Summary

| Section | Controls | Target Pass Rate |
|---------|----------|-----------------|
| 1 - IAM | 22 | 80% |
| 2 - Storage | 5 | 80% |
| 3 - Logging | 11 | 90% |
| 4 - Monitoring | 15 | 85% |
| 5 - Networking | 5 | 85% |
| **Total** | **58** | **84%** |

Run `python3 aws/security-hub/cis-benchmark-checker.py` to get live scores from Security Hub.

---

*Results template — populate with actual Security Hub output*
*Generated by: cloud-soc-canada SOC Lab*
