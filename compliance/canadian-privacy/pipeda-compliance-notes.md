
# PIPEDA Compliance Notes — Cloud SOC Lab
## cloud-soc-canada

**Legislation:** Personal Information Protection and Electronic Documents Act (PIPEDA)
**Jurisdiction:** Federal Canada
**Applicability:** Applies to private-sector organisations collecting, using, or disclosing personal information in the course of commercial activities

---

## What Is PIPEDA?

PIPEDA is Canada's federal private-sector privacy law. It governs how organisations
collect, use, and disclose personal information. For a cloud SOC environment,
PIPEDA has direct implications for how security logs, incident data, and user
information are handled.

**Enforced by:** Office of the Privacy Commissioner of Canada (OPC)
**Updated by:** Bill C-11 / Bill C-27 (Consumer Privacy Protection Act — CPPA, pending as of 2024)

---

## Key PIPEDA Principles Relevant to SOC Operations

### 1. Accountability (Principle 1)
- Designate a Privacy Officer responsible for PIPEDA compliance
- Establish policies for handling personal information in logs
- **SOC Action:** Document who has access to CloudTrail, Sentinel, and Elasticsearch data

### 2. Identifying Purposes (Principle 2)
- State why personal information is being collected
- **SOC Action:** Document that logs are collected for security monitoring, incident response,
  and compliance — not marketing or profiling

### 3. Consent (Principle 3)
- Generally, consent is required unless security exception applies
- **SOC Exception:** Organisations may collect/use personal info without consent for
  fraud detection and security investigations

### 4. Limiting Collection (Principle 4)
- Collect only what is necessary for identified purposes
- **SOC Action:** Review CloudTrail, Sentinel, and GuardDuty data fields — disable collection
  of fields not needed for security monitoring

### 5. Limiting Use, Disclosure, and Retention (Principle 5)
- **Retention:** Only keep logs as long as necessary
- **SOC Action:** Current retention policy = 90 days (hot) + archive for serious incidents
- **Disclosure:** Only share log data with authorised SOC personnel and law enforcement
  under proper legal authority

### 6. Accuracy (Principle 6)
- Ensure information used in investigations is accurate
- **SOC Action:** Implement log integrity checks (CloudTrail file validation, Elasticsearch checksums)

### 7. Safeguards (Principle 7)
- Use technical and organisational measures to protect personal information
- **SOC Actions:**
  - Encrypt logs at rest (S3 AES-256, Azure encryption-at-rest)
  - Encrypt in transit (TLS for all API calls)
  - Role-based access to Elasticsearch and Kibana
  - MFA for all SOC analyst accounts

### 8. Openness (Principle 8)
- Make privacy practices available to the public
- **SOC Action:** Maintain internal privacy policy for log handling

### 9. Individual Access (Principle 9)
- Individuals can request access to their personal information
- **SOC Action:** Establish a process to respond to access requests within 30 days

### 10. Challenging Compliance (Principle 10)
- Individuals can challenge the organisation's compliance
- **SOC Action:** Maintain a complaints procedure

---

## Personal Information in Security Logs

The following types of personal information may appear in cloud security logs:

| Data Type | Source | PIPEDA Implication |
|-----------|--------|-------------------|
| Email / UPN | Azure SigninLogs, AuditLogs | PII — access controls required |
| IP Address | CloudTrail, GuardDuty, SigninLogs | PII in Canada (can identify individuals) |
| AWS Account ID | CloudTrail | Internal — lower risk if not linked to a person |
| User Agent strings | CloudTrail | May identify device/OS — treat as PII |
| Geographic location | GeoIP enrichment | PII — store minimally |
| API call parameters | CloudTrail requestParameters | May contain resource names with PII |

---

## Breach Notification Requirements

Under PIPEDA (amended by the *Security of Personal Information Regulations*, in force since November 2018):

- **When to report:** Report to the OPC when a breach creates a **real risk of significant harm** to individuals
- **Timeline:** Report to OPC and affected individuals **as soon as feasible**
- **Record keeping:** Keep records of ALL breaches (even those not reported) for **24 months**

### SOC Breach Assessment Checklist

When a cloud security incident involves personal information:

- [ ] Was personal information accessed, used, disclosed, or lost?
- [ ] If yes — assess **probability of harm**: sensitivity of info, number of individuals, re-identification risk
- [ ] Is there a real risk of significant harm (financial, reputational, physical, psychological)?
- [ ] If yes → notify OPC and affected individuals
- [ ] Log the breach in the 24-month breach register regardless of notification decision

---

## Data Retention Schedule (PIPEDA Compliant)

| Log Type | Hot Retention | Archive | Deletion |
|----------|-------------|---------|---------|
| CloudTrail events | 90 days | 1 year | Delete after 1 year |
| GuardDuty findings | 90 days | 1 year | Delete after 1 year |
| Azure SigninLogs | 90 days | 1 year | Delete after 1 year |
| Security Hub findings | 90 days | 1 year | Delete after 1 year |
| Incident reports | Indefinite | — | Delete when no longer needed |
| Breach records | 24 months minimum | Per OPC guidance | After 24 months |

---

## Canadian Region Advantage

Storing logs in **ca-central-1** (AWS) and **canadacentral** (Azure) ensures:
- Data physically resides in Canada
- Subject to Canadian law (PIPEDA) rather than US CLOUD Act
- Easier compliance for Canadian clients who require domestic data residency
- Azure Canada Central has a **data residency guarantee**

---

*Last reviewed: 2024 | Review annually or when legislation changes*
*Reference: https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/*
