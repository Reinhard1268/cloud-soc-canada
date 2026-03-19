# Architecture Document — Cloud-Native SOC Monitoring
## cloud-soc-canada

**Version:** 1.0  
**Author:** SOC Lab | Amoah Reinhard  
**Region:** AWS ca-central-1 + Azure canadacentral  
**Stack:** Wazuh + Elastic + TheHive + Shuffle (Project 1) + Cloud Sources (Project 6)

---

## Overview

Project 06-cloud-soc-canada extends the on-premises HomeSOC-Enterprise (Project 1)
to ingest, normalise, detect, and respond to security events originating from
AWS Canada Central and Azure Canada Central cloud environments.

All data remains within Canadian geographic boundaries, satisfying PIPEDA
data residency requirements and providing a competitive advantage when
presenting this portfolio to Canadian employers.

---

## AWS Architecture (ca-central-1)

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS ca-central-1                          │
│                                                             │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │ CloudTrail  │   │  GuardDuty   │   │  Security Hub   │  │
│  │ (all APIs)  │   │  (threats)   │   │  (CIS + FSBP)   │  │
│  └──────┬──────┘   └──────┬───────┘   └────────┬────────┘  │
│         │                 │                     │           │
│         ▼                 ▼                     ▼           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              S3 Bucket (Encrypted, ca-central-1)     │   │
│  │         soc-lab-cloudtrail-logs-ca-{account_id}      │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                              │                              │
│  ┌───────────────────────────▼──────────────────────────┐  │
│  │                   EventBridge                         │  │
│  │     Routes findings → SNS → SOC notification          │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │    IAM    │  │  CloudWatch  │  │   VPC Flow Logs    │   │
│  │ (identity)│  │  Log Groups  │  │   (network)        │   │
│  └───────────┘  └──────────────┘  └────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    Python Forwarders
              (cloudtrail-to-elastic.py,
               guardduty-findings-to-elastic.py,
               security-hub-to-elastic.py,
               log-forwarder.py --source aws)
```

---

## Azure Architecture (canadacentral)

```
┌─────────────────────────────────────────────────────────────┐
│                  Azure canadacentral                         │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Azure AD    │  │  Azure       │  │  Microsoft       │  │
│  │  SigninLogs  │  │  Activity    │  │  Sentinel        │  │
│  │  AuditLogs   │  │  Logs        │  │  (8 rules)       │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                    │            │
│         ▼                 ▼                    ▼            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Log Analytics Workspace (canadacentral)       │  │
│  │              soc-lab-workspace (90d retention)        │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │                               │
│  ┌──────────────────────────▼───────────────────────────┐  │
│  │           Microsoft Defender for Cloud               │  │
│  │        (CIS Benchmark + MCSB assessments)            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Azure NSGs  │  │  Key Vault   │  │  Storage Accts   │  │
│  │  (network)   │  │  (secrets)   │  │  (blob logging)  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    Python Forwarders
              (azure-logs-to-elastic.py,
               log-forwarder.py --source azure)
```

---

## Data Flow: Cloud Events → Elastic → TheHive

```
Cloud Sources (AWS + Azure)
         │
         ▼
┌─────────────────────┐
│   Python Forwarders  │  ← log-forwarder.py (unified)
│   (every 5 min)      │     cloudtrail-to-elastic.py
│                      │     guardduty-findings-to-elastic.py
│   ECS Normalisation  │     azure-logs-to-elastic.py
└──────────┬───────────┘
           │
           ▼
┌─────────────────────┐
│   Elasticsearch      │  ← http://localhost:9200
│   (from Project 1)   │
│                      │     Indices:
│   Ingest Pipeline    │     ├── aws-cloudtrail-events
│   (normalise/enrich) │     ├── aws-guardduty-findings
└──────────┬───────────┘     ├── aws-security-hub-findings
           │                 └── azure-sentinel-alerts
           ▼
┌─────────────────────┐
│   alert-enricher.py  │  ← Enriches: GeoIP, ASN, AbuseIPDB,
│   (continuous)       │     MITRE ATT&CK, Risk Score
│                      │
│   Risk Score > 70?   │
└──────────┬───────────┘
           │
     ┌─────┴──────┐
     ▼            ▼
┌─────────┐  ┌──────────┐
│  Kibana  │  │ TheHive  │  ← Alerts for HIGH/CRITICAL
│ Dashboard│  │ (alerts) │
│ (Project1)  └────┬─────┘
└─────────┘       │
                  ▼
          ┌──────────────┐
          │   Shuffle     │  ← SOAR playbooks (Project 3)
          │   (SOAR)      │
          └──────────────┘
```

---

## Canadian Compliance Architecture

```
┌────────────────────────────────────────────────────────────┐
│                CANADIAN DATA BOUNDARY                       │
│                                                            │
│   ┌──────────────────┐    ┌─────────────────────────────┐  │
│   │  AWS ca-central-1│    │   Azure canadacentral        │  │
│   │  (Toronto, ON)   │    │   (Toronto, ON)              │  │
│   │                  │    │                              │  │
│   │  • CloudTrail    │    │  • Log Analytics Workspace   │  │
│   │  • GuardDuty     │    │  • Microsoft Sentinel        │  │
│   │  • Security Hub  │    │  • Defender for Cloud        │  │
│   │  • S3 (logs)     │    │  • Storage Accounts          │  │
│   └──────────────────┘    └─────────────────────────────┘  │
│                                                            │
│   ┌────────────────────────────────────────────────────┐   │
│   │   On-Premises (Kali Linux — Physical Canada)       │   │
│   │                                                    │   │
│   │   Elasticsearch ← Wazuh ← TheHive ← Shuffle       │   │
│   │   (HomeSOC-Enterprise from Project 1)              │   │
│   └────────────────────────────────────────────────────┘   │
│                                                            │
│   PIPEDA Compliance:                                       │
│   ✅ All data at rest in Canada                            │
│   ✅ All data in transit encrypted (TLS)                   │
│   ✅ 90-day retention policy                               │
│   ✅ Access controls (IAM/RBAC)                            │
│   ✅ Breach notification process documented                │
└────────────────────────────────────────────────────────────┘
```

---

## Integration with On-Premises SOC (Project 1)

The cloud monitoring layer integrates with the existing HomeSOC-Enterprise:

| Component (Project 1) | Role in Project 6 |
|----------------------|-------------------|
| Elasticsearch 8.x | Receives all cloud log forwards via Python scripts |
| Kibana 5601 | Hosts cloud-soc-dashboard.ndjson for cloud visibility |
| TheHive 5 | Receives HIGH/CRITICAL alerts from GuardDuty + Sentinel |
| Shuffle SOAR | Can trigger cloud remediation playbooks via webhooks |
| Wazuh | Monitors the Kali Linux host running the forwarder scripts |

### Wazuh Custom Rules for Cloud Forwarder

Add to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="cloud-soc,">
  <rule id="100600" level="10">
    <program_name>log-forwarder</program_name>
    <match>ERROR</match>
    <description>Cloud log forwarder error — check connectivity</description>
  </rule>
  <rule id="100601" level="3">
    <program_name>log-forwarder</program_name>
    <match>indexed=0</match>
    <description>Cloud forwarder — zero events indexed this cycle</description>
  </rule>
</group>
```

---

## Cost Estimate (Free Tier)

### AWS Free Tier (12 months)

| Service | Free Tier Limit | SOC Lab Usage | Est. Cost |
|---------|----------------|---------------|-----------|
| CloudTrail | 1 trail free | 1 trail | $0.00 |
| S3 | 5GB free | <1GB logs/month | $0.00 |
| CloudWatch Logs | 5GB free | <1GB/month | $0.00 |
| GuardDuty | 30-day free trial | All findings | $0.00 (trial) |
| Security Hub | 30-day free trial | All findings | $0.00 (trial) |
| **After free tier** | | | ~$5-15/month |

### Azure Free Account ($200 credit / 30 days)

| Service | Free Credit Usage | Est. Monthly After |
|---------|------------------|--------------------|
| Log Analytics | 5GB/day free | $2.99/GB over 5GB |
| Microsoft Sentinel | Free on free-tier workspace | $2.46/GB after trial |
| Defender for Cloud | Free CSPM | $0.007/server-hr for enhanced |
| **Total lab estimate** | Within free credit | ~$5-20/month |

### Tips to Stay Within Free Tier

- Set AWS billing alerts at $1 and $5
- Use `aws budgets create-budget` to auto-alert
- Set Azure spending limit in Cost Management
- Disable GuardDuty and Security Hub when not actively testing
- Use `--dry-run` flag on forwarders to test without indexing

---

## Scaling Considerations

For production deployment beyond the lab:

1. **Multi-Account:** Deploy AWS Organizations with delegated GuardDuty admin
2. **Multi-Region:** Extend to ca-west-1 (Calgary) for full Canadian coverage
3. **Azure Multi-Subscription:** Use Azure Lighthouse for cross-subscription management
4. **High Availability:** Deploy Elasticsearch cluster (3 nodes) instead of single node
5. **Log Volume:** At enterprise scale, consider Kafka as a buffer between cloud sources and Elasticsearch
6. **Automation:** Expand Shuffle SOAR playbooks to auto-invoke remediation scripts
7. **Compliance:** Engage AWS Canada Compliance Programs and Microsoft Canada Trust Center

---

## Detection Coverage Summary

| MITRE Tactic | AWS Detection | Azure Detection |
|-------------|---------------|-----------------|
| Initial Access | CloudTrail ConsoleLogin, GuardDuty UnauthorizedAccess | Sentinel impossible-travel, brute-force |
| Persistence | IAM escalation rules (aws-iam-001 to 008) | Sentinel new-admin-account, iam-privilege-escalation |
| Privilege Escalation | AdministratorAccess attach, root usage | Sentinel iam-privilege-escalation, suspicious-api |
| Defense Evasion | StopLogging, DeleteTrail detection | Sentinel lateral-movement |
| Credential Access | GetSecretValue rules, access key anomalies | Sentinel brute-force-azure |
| Discovery | Bulk IAM read operations | Sentinel suspicious-api-activity |
| Lateral Movement | AssumeRole cross-account | Sentinel lateral-movement-azure |
| Collection | S3 GetObject volume | Sentinel data-exfiltration |
| Exfiltration | S3 public ACL, cross-account replication | Sentinel data-exfiltration, geo-block |
| Impact | GuardDuty CryptoCurrency findings | Sentinel crypto-mining-detection |

---

*Architecture document for 06-cloud-soc-canada*  
*Part of a 10-project cybersecurity portfolio targeting Junior Security Analyst roles in Canada*  
*GitHub: cloud-soc-canada*
