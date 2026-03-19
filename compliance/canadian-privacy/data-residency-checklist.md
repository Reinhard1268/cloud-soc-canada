
# Data Residency Checklist — Canadian Cloud SOC

**Purpose:** Ensure all cloud resources, log storage, and data processing
remain within Canadian geographic boundaries to satisfy data residency
requirements for Canadian clients and PIPEDA compliance.

---

## AWS Canada — ca-central-1

### Region Verification

- [ ] AWS CLI default region set to `ca-central-1`
  ```bash
  aws configure get region  # Should return: ca-central-1
  ```
- [ ] CloudTrail trail is `IsMultiRegionTrail: true` but S3 bucket is in `ca-central-1`
- [ ] All S3 buckets for log storage are in `ca-central-1`
  ```bash
  aws s3api get-bucket-location --bucket YOUR_BUCKET
  # Should return: "LocationConstraint": "ca-central-1"
  ```
- [ ] GuardDuty detector is created in `ca-central-1`
  ```bash
  aws guardduty list-detectors --region ca-central-1
  ```
- [ ] Security Hub is enabled in `ca-central-1`
- [ ] CloudWatch Log Groups are in `ca-central-1`
- [ ] SNS topics are in `ca-central-1`
- [ ] EventBridge rules are in `ca-central-1`

### Services Available in ca-central-1

| Service | Available in ca-central-1 | Notes |
|---------|--------------------------|-------|
| CloudTrail | Yes | Multi-region trail supported |
| GuardDuty | Yes | All protection types available |
| Security Hub | Yes | CIS + FSBP standards |
| S3 | Yes | All features |
| CloudWatch | Yes | Logs + Metrics |
| Inspector v2 | Yes | EC2 + Lambda |
| Macie | Limited | Check current availability |
| IAM Access Analyzer | Yes | |
| Detective | Yes | Requires GuardDuty |

### Known AWS Data Residency Limitations

- **IAM** is a global service — IAM API calls may be logged in `us-east-1`
- **Route 53** is a global service — DNS logs may process outside Canada
- **CloudFront** — edge locations are outside Canada; logs may be written globally
- **Global Accelerator** — processing occurs globally

---

## Azure Canada — canadacentral

### Region Verification

- [ ] Default Azure location set to `canadacentral`
  ```bash
  az configure --defaults location=canadacentral
  az configure --list-defaults | grep location
  ```
- [ ] Log Analytics workspace is in `canadacentral`
  ```bash
  az monitor log-analytics workspace show \
    --resource-group soc-lab-rg \
    --workspace-name soc-lab-workspace \
    --query location
  # Should return: "canadacentral"
  ```
- [ ] Resource group is in `canadacentral`
- [ ] Azure Sentinel (Microsoft Sentinel) is tied to `canadacentral` workspace
- [ ] Event Hub (if used) is in `canadacentral`
- [ ] Storage accounts for log archiving are in `canadacentral`

### Azure Canada Regions

| Region | Location | Pair |
|--------|----------|------|
| canadacentral | Toronto, ON | canadaeast |
| canadaeast | Quebec City, QC | canadacentral |

**Recommended:** Use `canadacentral` (Toronto) as primary, `canadaeast` as DR.

### Azure Data Residency Guarantee

Microsoft Azure Canada Central provides:
- **Data at rest** stored in Canada
- **Data in transit** encrypted via TLS
- **Microsoft Privacy Commitment** for Canadian data

Reference: https://azure.microsoft.com/en-ca/explore/global-infrastructure/data-residency/

### Azure AD Note

Azure Active Directory stores some data in US or EU regions depending on tenant
configuration. For full Canadian data residency of identity data, verify:

```bash
az ad signed-in-user show --query "onPremisesDistinguishedName"
# Check tenant data location at: https://admin.microsoft.com/AdminPortal/Home#/Settings/OrganizationProfile
```

---

## Elasticsearch (On-Premises — Kali Linux)

- [ ] Elasticsearch running on local Kali Linux machine (`localhost:9200`)
- [ ] Data stored locally — no cloud replication to foreign regions
- [ ] Kibana accessible only on local network
- [ ] No Elastic Cloud subscription that routes data internationally

---

## Cross-Border Data Transfer Risks

| Scenario | Risk | Mitigation |
|----------|------|-----------|
| Using AWS global services (IAM, Route 53) | Some logs may process in us-east-1 | Acceptable — metadata only, not log content |
| Azure AD tenant in US/EU region | Identity data may be outside Canada | Review tenant region; use Canadian tenant if required |
| Third-party threat intel APIs (AbuseIPDB, VirusTotal) | IP addresses sent to US-based services | Document in privacy policy; IPs alone are low-risk |
| GeoIP lookup (ip-api.com) | IP addresses sent to external service | Low-risk; consider self-hosted MaxMind DB for higher compliance |

---

## Compliance Sign-Off

| Item | Status | Date | Reviewer |
|------|--------|------|---------|
| AWS resources in ca-central-1 | Pending | | |
| Azure resources in canadacentral | Pending | | |
| Elasticsearch on-prem (local) | Pending | | |
| Retention policy configured | Pending | | |
| Access controls reviewed | Pending | | |
| PIPEDA notes reviewed | Pending | | |

---

*Checklist maintained by SOC Lab — 06-cloud-soc-canada*
*Review quarterly or when new cloud services are added*
