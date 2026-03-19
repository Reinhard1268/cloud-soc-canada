# IAM Privilege Escalation — Incident Response Playbook

**Project:** cloud-soc-canada  
**Version:** 1.0  
**Region:** ca-central-1 (AWS) / canadacentral (Azure)  
**Classification:** INTERNAL — SOC USE ONLY

---

## Overview

This playbook guides SOC analysts through detecting, investigating, and
remediating IAM privilege escalation incidents across AWS and Azure
environments in the Canadian region.

**MITRE ATT&CK Coverage:** T1078, T1098, T1136, T1548  
**Estimated Time to Contain:** 15–45 minutes

---

## Triage Criteria

| Severity | Trigger Examples |
|----------|-----------------|
| CRITICAL | Root account used, Global Admin assigned, AdministratorAccess attached |
| HIGH | Admin role assigned outside hours, new admin account < 7 days old, trust policy changed |
| MEDIUM | Direct user policy attachment, IAM user enumeration burst |

---

## Phase 1: Detection & Initial Triage (0–5 min)

### 1.1 Alert Received

When a GuardDuty, Sentinel, or Elasticsearch alert fires for IAM escalation:

1. Note the **alert timestamp**, **affected identity** (IAM user/role ARN or Azure UPN), and **source IP**.
2. Open the alert in TheHive — review the automated enrichment (GeoIP, ASN, AbuseIPDB score).
3. Check if the identity is a **known service account** by searching the asset inventory.
4. Determine **blast radius**: what resources can this identity access?

### 1.2 AWS — Quick Triage Commands
```bash
# Who is this identity?
aws iam get-user --user-name SUSPECT_USER

# What policies are attached?
aws iam list-attached-user-policies --user-name SUSPECT_USER
aws iam list-user-policies --user-name SUSPECT_USER
aws iam list-groups-for-user --user-name SUSPECT_USER

# Recent API activity in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=SUSPECT_USER \
  --start-time $(date -d '2 hours ago' --iso-8601=seconds) \
  --region ca-central-1

# Active access keys
aws iam list-access-keys --user-name SUSPECT_USER
```

### 1.3 Azure — Quick Triage Commands
```bash
# Who is this UPN?
az ad user show --id suspect@domain.com

# What roles are assigned?
az role assignment list --assignee suspect@domain.com --all

# Recent sign-ins (last 2 hours via KQL)
# Run in Log Analytics:
# SigninLogs | where UserPrincipalName == "suspect@domain.com" | where TimeGenerated >= ago(2h)

# Recent audit activity
# AuditLogs | where InitiatedBy.user.userPrincipalName == "suspect@domain.com" | where TimeGenerated >= ago(2h)
```

---

## Phase 2: Investigation (5–20 min)

### 2.1 Determine If Legitimate

Ask these questions:

- Is this a **scheduled maintenance window** or change request?
- Is the source IP from a **known corporate IP range**?
- Does the **manager or owner** of this account confirm the activity?
- Was there a **ticket or approval** for this role assignment?

If YES to all → document as false positive, tune suppression rule.  
If NO to any → escalate to Phase 3 (Containment).

### 2.2 Timeline Reconstruction

Build a 24-hour activity timeline for the suspect identity:

**AWS — CloudTrail Timeline Query (Elasticsearch)**
```
GET aws-cloudtrail-events/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "user.name": "SUSPECT_USER" }},
        { "range": { "@timestamp": { "gte": "now-24h" }}}
      ]
    }
  },
  "sort": [{ "@timestamp": "asc" }],
  "size": 500
}
```

**Azure — Log Analytics KQL**
```kql
union SigninLogs, AuditLogs, AzureActivity
| where TimeGenerated >= ago(24h)
| where InitiatedBy.user.userPrincipalName == "suspect@domain.com"
   or Caller == "suspect@domain.com"
| order by TimeGenerated asc
```

### 2.3 Lateral Movement Check

Check if the escalated identity was used to access other accounts/resources:

**AWS:**
```bash
# Check for AssumeRole from this identity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --region ca-central-1 | grep SUSPECT_USER

# Check for newly created IAM users/roles
aws iam list-users --query 'Users[?CreateDate>=`INCIDENT_DATE`]'
aws iam list-roles --query 'Roles[?CreateDate>=`INCIDENT_DATE`]'
```

**Azure:**
```kql
AuditLogs
| where TimeGenerated >= ago(24h)
| where OperationName has_any ("Add user","Add service principal","Add member to role")
| extend Actor=tostring(InitiatedBy.user.userPrincipalName)
| where Actor == "suspect@domain.com"
```

---

## Phase 3: Containment (15–30 min)

### 3.1 AWS Containment Actions

**Disable compromised access key immediately:**
```bash
aws iam update-access-key \
  --user-name SUSPECT_USER \
  --access-key-id AKIAXXXXXXXXXXXXXXXX \
  --status Inactive \
  --region ca-central-1

# Or use the automated remediation script:
python3 scripts/remediation/aws-auto-remediate.py \
  --action disable-access-key \
  --user SUSPECT_USER \
  --key-id AKIAXXXXXXXXXXXXXXXX \
  --auto-approve
```

**Detach over-permissive policies:**
```bash
aws iam detach-user-policy \
  --user-name SUSPECT_USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Or use the automated remediation script:
python3 scripts/remediation/aws-auto-remediate.py \
  --action revoke-iam-permissions \
  --user SUSPECT_USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --auto-approve
```

**Add deny-all policy as emergency brake:**
```bash
aws iam put-user-policy \
  --user-name SUSPECT_USER \
  --policy-name emergency-deny-all \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]
  }'
```

### 3.2 Azure Containment Actions

**Disable compromised Azure AD account:**
```bash
az ad user update \
  --id suspect@domain.com \
  --account-enabled false

# Or via remediation script:
python3 scripts/remediation/azure-auto-remediate.py \
  --action disable-user \
  --user-id suspect@domain.com \
  --auto-approve
```

**Revoke role assignment:**
```bash
ASSIGNMENT_ID=$(az role assignment list \
  --assignee suspect@domain.com \
  --query '[0].id' -o tsv)
az role assignment delete --ids $ASSIGNMENT_ID

# Or via remediation script:
python3 scripts/remediation/azure-auto-remediate.py \
  --action revoke-role \
  --user suspect@domain.com \
  --role "Global Administrator" \
  --auto-approve
```

**Revoke all active sessions:**
```bash
az ad user revoke-sign-in-sessions --id suspect@domain.com
```

---

## Phase 4: Eradication (30–45 min)

1. Audit all resources the escalated identity touched during the incident window.
2. Remove any backdoor accounts, roles, or policies created by the attacker.
3. Rotate all access keys and secrets associated with the compromised account.
4. Review and revert any trust policy changes on IAM roles.
5. Scan for newly created Lambda functions, EC2 instances, or Azure VMs.
6. Check for new SNS subscriptions, SQS queues, or S3 buckets (data exfil staging).

---

## Phase 5: Recovery & Hardening

1. Re-enable account with MFA enforced.
2. Apply least-privilege policy (replace broad policies with scoped ones).
3. Enable AWS IAM Access Analyzer or Azure AD Access Reviews.
4. Add the compromised identity's activity pattern to detection rules.
5. Update GuardDuty suppression rules to remove any false positive that delayed detection.

---

## Phase 6: Post-Incident Documentation

Complete in TheHive:

- [ ] Timeline of events from first indicator to containment
- [ ] Root cause (phishing / stolen credentials / insider / misconfiguration)
- [ ] Affected resources and data exposure assessment
- [ ] Actions taken (with timestamps)
- [ ] Lessons learned
- [ ] Detection rule improvements
- [ ] PIPEDA breach notification assessment (if PII accessed)

---

## Detection Rule Improvement Checklist

After each IAM escalation incident:

- [ ] Was the escalation detected within SLA (< 15 min)?
- [ ] Were there any suppressed alerts that should have fired?
- [ ] Is there a new escalation technique to add to detection rules?
- [ ] Should the compromised account's IP/ASN be added to threat intel?

---

*Playbook maintained by SOC Lab — cloud-soc-canada*  
*Review quarterly or after every escalation incident*
