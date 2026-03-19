
# Zero Trust Architecture Notes
## cloud-soc-canada | Canadian Cloud SOC

**Framework:** NIST SP 800-207 Zero Trust Architecture
**Applied to:** AWS ca-central-1 + Azure canadacentral + On-Prem SOC Lab

---

## Zero Trust Principles

Zero Trust operates on the assumption that threats exist both inside and outside
traditional network boundaries. The core principle: **never trust, always verify**.

### The Three Core Tenets

1. **Verify Explicitly** — Always authenticate and authorise based on all available data points
   (identity, location, device, service, workload, data classification, anomalies)

2. **Use Least Privilege Access** — Limit user access with just-in-time and just-enough-access,
   risk-based adaptive policies, and data protection

3. **Assume Breach** — Minimise blast radius, segment access, verify end-to-end encryption,
   use analytics to get visibility, drive threat detection and improve defences

---

## Zero Trust Pillars Applied to This Lab

### Pillar 1: Identity

| Control | AWS Implementation | Azure Implementation | Status |
|---------|-------------------|---------------------|--------|
| Strong MFA for all users | IAM MFA enforcement | Azure AD MFA / Conditional Access | Implement |
| Privileged Identity Management | IAM roles + STS AssumeRole | Azure PIM just-in-time | Implement |
| No standing admin access | Remove permanent AdministratorAccess | PIM eligible assignments only | Implement |
| Identity analytics | CloudTrail + GuardDuty IAM findings | Azure AD Identity Protection | Active |
| Service-to-service auth | IAM instance roles / IRSA | Managed Identities | Implement |

**Lab Actions:**
```bash
# AWS: Enforce MFA for all console users
aws iam create-policy --policy-name RequireMFA --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "NotAction": ["iam:CreateVirtualMFADevice","iam:EnableMFADevice","iam:GetUser","iam:ListMFADevices","iam:ListVirtualMFADevices","iam:ResyncMFADevice","sts:GetSessionToken"],
    "Resource": "*",
    "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
  }]
}'

# Azure: Enforce Conditional Access MFA for admins
# Navigate: Azure AD > Security > Conditional Access > New Policy
# Assign to: All admin roles
# Grant: Require MFA
```

---

### Pillar 2: Devices

| Control | Implementation | Status |
|---------|---------------|--------|
| Managed device enforcement | Azure AD device compliance policies | Implement |
| Device health attestation | Intune compliance + Conditional Access | Optional for lab |
| Endpoint Detection & Response | Microsoft Defender for Endpoint | Optional |
| Certificate-based auth | AWS client VPN with mutual TLS | Implement for production |

---

### Pillar 3: Networks

| Control | AWS Implementation | Azure Implementation | Status |
|---------|-------------------|---------------------|--------|
| Micro-segmentation | VPC security groups + NACLs | NSGs + Azure Firewall | Implement |
| No implicit internal trust | Security groups deny all by default | NSGs deny all by default | Implement |
| Encrypted in-transit | TLS 1.2+ for all services | TLS 1.2+ enforced | Active |
| Network monitoring | VPC Flow Logs → CloudWatch | NSG Flow Logs → Log Analytics | Implement |
| Block internet exposure | No 0.0.0.0/0 inbound rules | No Any-to-Any NSG rules | Implement |

**Lab Actions:**
```bash
# AWS: Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids YOUR_VPC_ID \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn YOUR_ROLE_ARN \
  --region ca-central-1

# Azure: Block RDP/SSH from internet on all NSGs
az network nsg rule create \
  --resource-group soc-lab-rg \
  --nsg-name soc-lab-nsg \
  --name DenyAllInternetInbound \
  --priority 4096 \
  --source-address-prefixes Internet \
  --destination-port-ranges '*' \
  --access Deny \
  --protocol '*' \
  --direction Inbound
```

---

### Pillar 4: Applications

| Control | AWS Implementation | Azure Implementation | Status |
|---------|-------------------|---------------------|--------|
| App-level authentication | Cognito / API Gateway auth | Azure AD App Registrations | Implement |
| API security | WAF + API Gateway throttling | Azure API Management + WAF | Implement |
| Secrets management | AWS Secrets Manager + KMS | Azure Key Vault | Implement |
| Least-privilege service accounts | IAM roles (no long-term keys) | Managed Identities | Implement |
| Code signing / supply chain | CodeArtifact + Sigstore | Azure Artifacts + signing | Optional |

**Lab Actions:**
```bash
# AWS: Move credentials to Secrets Manager
aws secretsmanager create-secret \
  --name soc-lab/elastic-credentials \
  --description "Elasticsearch credentials for SOC lab" \
  --secret-string '{"username":"elastic","password":"YOUR_PASSWORD"}' \
  --region ca-central-1

# Rotate secrets automatically
aws secretsmanager rotate-secret \
  --secret-id soc-lab/elastic-credentials \
  --rotation-rules AutomaticallyAfterDays=30 \
  --region ca-central-1
```

---

### Pillar 5: Data

| Control | AWS Implementation | Azure Implementation | Status |
|---------|-------------------|---------------------|--------|
| Data classification | Macie for S3 | Microsoft Purview | Optional |
| Encryption at rest | S3 AES-256 / KMS | Azure SSE + Key Vault | Active |
| Encryption in transit | TLS 1.2+ enforced | TLS 1.2+ enforced | Active |
| Data loss prevention | S3 block public access | Azure Storage public access off | Active |
| Backup and recovery | S3 versioning + lifecycle | Azure Backup | Implement |
| Canadian data residency | ca-central-1 only | canadacentral only | Active |

---

### Pillar 6: Visibility and Analytics (SOC Focus)

This is where the SOC lab directly implements Zero Trust analytics:

| Control | Implementation | Status |
|---------|---------------|--------|
| Centralised log aggregation | Elasticsearch + Kibana | Active |
| Real-time threat detection | GuardDuty + Sentinel rules | Active |
| Behavioural analytics | ML anomaly detection (Elastic) | Active |
| SOAR automation | Shuffle + TheHive playbooks | Active (Project 3) |
| Incident response | TheHive case management | Active (Project 1) |
| Continuous compliance monitoring | Security Hub + CIS benchmarks | Active |

---

## Zero Trust Maturity Model

Based on CISA Zero Trust Maturity Model (2023):

| Pillar | Traditional | Advanced | Optimal | Lab Current |
|--------|-------------|----------|---------|-------------|
| Identity | Static MFA | Risk-based MFA | Continuous validation | Advanced |
| Devices | Known/managed | Compliance gates | Real-time health | Traditional |
| Networks | Macro-segmentation | Micro-segmentation | Dynamic isolation | Advanced |
| Applications | On-prem auth | SSO + MFA | Least-privilege continuous | Advanced |
| Data | Perimeter encryption | Data-level controls | Automated DLP | Advanced |
| Visibility | SIEM | XDR | Predictive analytics | Advanced |

**Lab Overall Maturity: Advanced (targeting Optimal)**

---

## Zero Trust for Canadian Context

### Specific Canadian Requirements

1. **PIPEDA alignment** — Zero Trust's principle of minimal data collection aligns with PIPEDA's limiting-collection principle
2. **Sovereign cloud** — All data in ca-central-1 / canadacentral supports data sovereignty
3. **RCMP/CSIS considerations** — Canadian federal agencies may have enhanced requirements; this lab uses civilian-grade controls
4. **CCCS guidance** — Canadian Centre for Cyber Security recommends ZTA for federal departments (ITSM.10.089)

### References

- NIST SP 800-207: https://doi.org/10.6028/NIST.SP.800-207
- CISA Zero Trust Maturity Model: https://www.cisa.gov/zero-trust-maturity-model
- CCCS ITSM.10.089: https://www.cyber.gc.ca/en/guidance/zero-trust-security-model-itsm10089
- AWS Zero Trust whitepaper: https://docs.aws.amazon.com/security/zero-trust
- Azure Zero Trust: https://learn.microsoft.com/en-us/security/zero-trust/

---

*Zero Trust notes maintained by SOC Lab — 06-cloud-soc-canada*
*Review annually or when architecture changes*
