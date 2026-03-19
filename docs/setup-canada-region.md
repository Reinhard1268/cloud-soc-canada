# Setup Guide — Cloud SOC Canada Region
## 06-cloud-soc-canada

**Author:** Amoah Reinhard  
**Target:** Junior Security Analyst / Junior Penetration Tester (Canada)  
**Prerequisites:** Kali Linux, 32GB RAM, Docker, AWS CLI, Azure CLI, Python 3.10+

---

## Overview

This guide walks through setting up the complete Cloud-Native SOC Monitoring
environment covering AWS ca-central-1 and Azure canadacentral, integrated
with your existing HomeSOC-Enterprise stack from Project 1.

---

## Step 1: AWS Account Setup (ca-central-1)

### 1.1 Create a Free Tier AWS Account

1. Go to https://aws.amazon.com/free/
2. Click **Create a Free Account**
3. Enter email, account name, payment info (won't be charged within free tier limits)
4. Complete phone verification
5. Select **Basic Support (Free)**

### 1.2 Set Default Region to ca-central-1

After logging in to AWS Console:

```bash
# Set default region via AWS CLI
aws configure set default.region ca-central-1

# Verify
aws configure get region
# Expected output: ca-central-1

# Set in console: top-right region dropdown → Canada (Central) ca-central-1
```

### 1.3 Create IAM User for Lab (Never Use Root)

```bash
# Create IAM user for SOC lab work
aws iam create-user --user-name soc-lab-admin

# Create access key
aws iam create-access-key --user-name soc-lab-admin

# Attach SOC permissions policy
aws iam attach-user-policy \
  --user-name soc-lab-admin \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-user-policy \
  --user-name soc-lab-admin \
  --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess

# Enable MFA (do this in Console: IAM → Users → soc-lab-admin → Security credentials)
```

### 1.4 Configure AWS CLI

```bash
aws configure
# AWS Access Key ID: <from step 1.3>
# AWS Secret Access Key: <from step 1.3>
# Default region name: ca-central-1
# Default output format: json

# Verify identity
aws sts get-caller-identity
```

### 1.5 Verify ca-central-1 Service Availability

```bash
# Check GuardDuty availability
aws guardduty list-detectors --region ca-central-1

# Check Security Hub availability
aws securityhub describe-hub --region ca-central-1

# Check S3 bucket creation
aws s3 mb s3://test-ca-central-$(aws sts get-caller-identity --query Account --output text) \
  --region ca-central-1
```

---

## Step 2: Run cloudtrail-setup.sh

```bash
cd 06-cloud-soc-canada/aws/cloudtrail-setup/

# Make executable
chmod +x cloudtrail-setup.sh

# Run the setup
bash cloudtrail-setup.sh

# Expected output:
# [OK] Bucket created: soc-lab-cloudtrail-logs-ca-XXXXXXXXXXXX
# [OK] Trail created: arn:aws:cloudtrail:ca-central-1:XXXXXXXXXXXX:trail/soc-lab-trail
# [OK] Logging started.

# Copy the output ARNs to your .env file
```

---

## Step 3: Run guardduty-setup.sh

```bash
cd 06-cloud-soc-canada/aws/guardduty-config/

chmod +x guardduty-setup.sh
bash guardduty-setup.sh

# Expected output:
# [OK] GuardDuty enabled. Detector ID: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# [OK] S3 Protection enabled.
# [OK] Threat intel uploaded.

# Copy the Detector ID to your .env:
# AWS_GUARDDUTY_DETECTOR_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## Step 4: Run security-hub-setup.sh

```bash
cd 06-cloud-soc-canada/aws/security-hub/

chmod +x security-hub-setup.sh
bash security-hub-setup.sh

# Expected output:
# [OK] Security Hub enabled.
# [OK] FSBP standard enabled.
# [OK] CIS benchmark enabled.
# [OK] GuardDuty integration enabled.
```

---

## Step 5: Azure Account Setup (canadacentral)

### 5.1 Create Free Azure Account

1. Go to https://azure.microsoft.com/en-ca/free/
2. Click **Start free** — you get $200 CAD credit for 30 days
3. Sign in with Microsoft account or create one
4. Complete identity verification

### 5.2 Set Default Location to canadacentral

```bash
# Install Azure CLI on Kali Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login
az login

# Set default subscription
az account set --subscription "YOUR_SUBSCRIPTION_ID"

# Set default location
az configure --defaults location=canadacentral

# Verify
az configure --list-defaults | grep location
# Expected: location canadacentral
```

### 5.3 Create App Registration for SOC Lab

```bash
# Create app registration (service principal for API access)
az ad app create --display-name "soc-lab-monitor"

# Create service principal
APP_ID=$(az ad app list --display-name soc-lab-monitor --query '[0].appId' -o tsv)
az ad sp create --id $APP_ID

# Create client secret
az ad app credential reset --id $APP_ID --display-name "soc-lab-secret"
# SAVE the output — clientId, clientSecret, tenantId

# Assign Reader role on subscription
az role assignment create \
  --assignee $APP_ID \
  --role "Reader" \
  --scope "/subscriptions/$(az account show --query id -o tsv)"

az role assignment create \
  --assignee $APP_ID \
  --role "Security Reader" \
  --scope "/subscriptions/$(az account show --query id -o tsv)"
```

### 5.4 Run diagnostic-settings.sh

```bash
# Load .env values first
export $(cat .env | grep -v '#' | xargs)

cd 06-cloud-soc-canada/azure/monitor-config/
chmod +x diagnostic-settings.sh
bash diagnostic-settings.sh

# Expected output:
# [OK] Resource group ready: soc-lab-rg
# [OK] Log Analytics workspace created: soc-lab-workspace
# [OK] Activity Log diagnostic settings configured.
```

---

## Step 6: Configure Filebeat for AWS + Azure

```bash
# Install Filebeat on Kali Linux
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install filebeat -y

# Copy AWS config
sudo cp elastic/cloud-ingest/aws-filebeat-config.yml /etc/filebeat/filebeat.yml

# Set environment variables for Filebeat
sudo tee /etc/filebeat/filebeat.env > /dev/null << EOF
AWS_ACCESS_KEY_ID=$(grep AWS_ACCESS_KEY_ID .env | cut -d= -f2)
AWS_SECRET_ACCESS_KEY=$(grep AWS_SECRET_ACCESS_KEY .env | cut -d= -f2)
AWS_CLOUDTRAIL_BUCKET=$(grep AWS_CLOUDTRAIL_BUCKET .env | cut -d= -f2)
ELASTIC_URL=$(grep ELASTIC_URL .env | cut -d= -f2)
ELASTIC_USER=$(grep ELASTIC_USER .env | cut -d= -f2)
ELASTIC_PASSWORD=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
EOF

# Test config
sudo filebeat test config -c /etc/filebeat/filebeat.yml

# Start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

---

## Step 7: Import Kibana Dashboards

```bash
# Make sure Kibana is running (from Project 1)
curl -s http://localhost:5601/api/status | python3 -m json.tool | head -5

# Import cloud SOC dashboard
curl -s -X POST http://localhost:5601/api/saved_objects/_import \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  -u elastic:$ELASTIC_PASSWORD \
  --form file=@elastic/dashboards/cloud-soc-dashboard.ndjson

# Verify import
echo "Dashboard imported. Open: http://localhost:5601/app/dashboards"
```

---

## Step 8: Import Sentinel Rules

```bash
# Install Azure CLI Sentinel extension
az extension add --name sentinel

# Deploy each rule ARM template
for rule in azure/sentinel-rules/*.json; do
  echo "Deploying: $rule"
  az deployment group create \
    --resource-group soc-lab-rg \
    --template-file "$rule" \
    --parameters workspaceName=soc-lab-workspace \
    --output none
  echo "  Done: $rule"
done
```

---

## Step 9: End-to-End Test

### 9.1 Generate Test AWS Events

```bash
# Trigger a CloudTrail event (list S3 buckets — harmless)
aws s3 ls --region ca-central-1

# Trigger an IAM event
aws iam list-users --region ca-central-1

# Simulate GuardDuty test finding
aws guardduty create-sample-findings \
  --detector-id $AWS_GUARDDUTY_DETECTOR_ID \
  --finding-types UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B \
  --region ca-central-1
```

### 9.2 Verify Events Appear in Kibana

```bash
# Check CloudTrail index
curl -s -u elastic:$ELASTIC_PASSWORD \
  "http://localhost:9200/aws-cloudtrail-events/_count" | python3 -m json.tool

# Check GuardDuty index
curl -s -u elastic:$ELASTIC_PASSWORD \
  "http://localhost:9200/aws-guardduty-findings/_count" | python3 -m json.tool

# Run the forwarder manually
python3 scripts/log-forwarder.py --source aws --service all --once --verbose
```

### 9.3 Verify Azure Events

```bash
# Run Azure forwarder
python3 scripts/log-forwarder.py --source azure --service sentinel --once

# Check Azure index
curl -s -u elastic:$ELASTIC_PASSWORD \
  "http://localhost:9200/azure-sentinel-alerts/_count" | python3 -m json.tool
```

---

## Step 10: Troubleshooting

### AWS Issues

| Problem | Fix |
|---------|-----|
| `NoCredentialsError` | Run `aws configure` and re-enter credentials |
| `InvalidClientTokenId` | Check AWS_ACCESS_KEY_ID is correct in .env |
| `AccessDenied` on GuardDuty | Attach `AmazonGuardDutyFullAccess` to IAM user |
| S3 bucket already exists | Bucket names are global — add your account ID suffix |
| CloudTrail not logging | Run `aws cloudtrail start-logging --name soc-lab-trail` |
| GuardDuty no findings | Use `create-sample-findings` to test |

### Azure Issues

| Problem | Fix |
|---------|-----|
| `AuthenticationError` | Re-run `az login` or check AZURE_CLIENT_SECRET in .env |
| Log Analytics workspace empty | Wait 10-15 min for first logs to arrive |
| Sentinel rules not firing | Check query window — rules need historical data |
| `ResourceNotFound` on NSG | Verify RESOURCE_GROUP matches your deployment |
| No SigninLogs | Requires Azure AD P1 license or Security Defaults enabled |

### Elasticsearch Issues

| Problem | Fix |
|---------|-----|
| Connection refused | Check `docker ps` — is Elasticsearch running from Project 1? |
| Authentication failed | Verify ELASTIC_PASSWORD in .env |
| Index not created | Run forwarder once manually with `--once --verbose` |
| Dashboard not loading | Re-import ndjson via Kibana Saved Objects UI |

---

## Start All Services

```bash
# Start continuous forwarder (both AWS + Azure)
python3 scripts/log-forwarder.py --source both --service all &

# Start alert enricher
python3 scripts/alert-enricher.py --mode continuous &

# Start CloudTrail → Elastic direct forwarder
python3 aws/cloudtrail-setup/cloudtrail-to-elastic.py &

# Start GuardDuty → Elastic
python3 aws/guardduty-config/guardduty-findings-to-elastic.py &

# Start Azure → Elastic
python3 azure/log-analytics/azure-logs-to-elastic.py &

echo "All forwarders running. Check logs/ directory for activity."
```

---

*Setup guide for 06-cloud-soc-canada — Canadian employer portfolio project*
