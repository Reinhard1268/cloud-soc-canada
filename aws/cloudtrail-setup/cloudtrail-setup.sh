#!/usr/bin/env bash
# =============================================================
# cloudtrail-setup.sh
# Sets up AWS CloudTrail for SOC Lab in ca-central-1
# Usage: bash cloudtrail-setup.sh
# =============================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Configuration ─────────────────────────────────────────────
REGION="ca-central-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null \
             || error "AWS CLI not configured. Run: aws configure")
BUCKET_NAME="soc-lab-cloudtrail-logs-ca-${ACCOUNT_ID}"
TRAIL_NAME="soc-lab-trail"
LOG_GROUP="/aws/cloudtrail/soc-lab"
SNS_TOPIC="soc-lab-cloudtrail-alerts"
CW_ROLE_NAME="CloudTrail-CloudWatch-Role"
LIFECYCLE_FILE="/tmp/cloudtrail-lifecycle.json"
POLICY_FILE="/tmp/cloudtrail-bucket-policy.json"

echo ""
echo "=============================================="
echo "  SOC Lab — CloudTrail Setup (ca-central-1)"
echo "=============================================="
echo ""

# ── 1. Verify AWS CLI region ──────────────────────────────────
info "Verifying AWS CLI is configured for ${REGION}..."
CURRENT_REGION=$(aws configure get region || echo "none")
if [[ "$CURRENT_REGION" != "$REGION" ]]; then
  warn "Default region is '${CURRENT_REGION}'. Overriding to ${REGION} for this script."
  export AWS_DEFAULT_REGION="${REGION}"
fi
success "Region: ${REGION} | Account: ${ACCOUNT_ID}"

# ── 2. Create S3 Bucket ───────────────────────────────────────
info "Creating S3 bucket: ${BUCKET_NAME}..."
if aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
  warn "Bucket ${BUCKET_NAME} already exists — skipping creation."
else
  aws s3api create-bucket \
    --bucket "${BUCKET_NAME}" \
    --region "${REGION}" \
    --create-bucket-configuration LocationConstraint="${REGION}"
  success "Bucket created: ${BUCKET_NAME}"
fi

# ── 3. Enable Versioning ──────────────────────────────────────
info "Enabling versioning on ${BUCKET_NAME}..."
aws s3api put-bucket-versioning \
  --bucket "${BUCKET_NAME}" \
  --versioning-configuration Status=Enabled
success "Versioning enabled."

# ── 4. Enable Server-Side Encryption (AES-256) ───────────────
info "Enabling AES-256 encryption on ${BUCKET_NAME}..."
aws s3api put-bucket-encryption \
  --bucket "${BUCKET_NAME}" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      },
      "BucketKeyEnabled": true
    }]
  }'
success "Encryption enabled."

# ── 5. Block All Public Access ────────────────────────────────
info "Blocking all public access on ${BUCKET_NAME}..."
aws s3api put-public-access-block \
  --bucket "${BUCKET_NAME}" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
BlockPublicPolicy=true,RestrictPublicBuckets=true
success "Public access blocked."

# ── 6. Lifecycle Policy (90-day retention) ────────────────────
info "Setting lifecycle policy (90-day retention)..."
cat > "${LIFECYCLE_FILE}" <<EOF
{
  "Rules": [
    {
      "ID": "cloudtrail-log-retention",
      "Status": "Enabled",
      "Filter": { "Prefix": "cloudtrail/" },
      "Expiration": { "Days": 90 },
      "NoncurrentVersionExpiration": { "NoncurrentDays": 30 }
    }
  ]
}
EOF
aws s3api put-bucket-lifecycle-configuration \
  --bucket "${BUCKET_NAME}" \
  --lifecycle-configuration "file://${LIFECYCLE_FILE}"
success "Lifecycle policy applied."

# ── 7. S3 Bucket Policy for CloudTrail ───────────────────────
info "Applying S3 bucket policy for CloudTrail service..."
cat > "${POLICY_FILE}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/cloudtrail/AWSLogs/${ACCOUNT_ID}/*",
      "Condition": {
        "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" }
      }
    },
    {
      "Sid": "DenyNonSSL",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
EOF
aws s3api put-bucket-policy \
  --bucket "${BUCKET_NAME}" \
  --policy "file://${POLICY_FILE}"
success "Bucket policy applied."

# ── 8. Create CloudWatch Log Group ───────────────────────────
info "Creating CloudWatch log group: ${LOG_GROUP}..."
if aws logs describe-log-groups \
     --log-group-name-prefix "${LOG_GROUP}" \
     --region "${REGION}" \
     --query 'logGroups[0].logGroupName' \
     --output text 2>/dev/null | grep -q "${LOG_GROUP}"; then
  warn "Log group already exists — skipping."
else
  aws logs create-log-group \
    --log-group-name "${LOG_GROUP}" \
    --region "${REGION}"
  aws logs put-retention-policy \
    --log-group-name "${LOG_GROUP}" \
    --retention-in-days 90 \
    --region "${REGION}"
  success "Log group created: ${LOG_GROUP}"
fi
LOG_GROUP_ARN=$(aws logs describe-log-groups \
  --log-group-name-prefix "${LOG_GROUP}" \
  --region "${REGION}" \
  --query 'logGroups[0].arn' --output text)

# ── 9. Create IAM Role for CloudWatch ────────────────────────
info "Creating IAM role for CloudTrail → CloudWatch..."
TRUST_POLICY='{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":{"Service":"cloudtrail.amazonaws.com"},
    "Action":"sts:AssumeRole"
  }]
}'
if aws iam get-role --role-name "${CW_ROLE_NAME}" 2>/dev/null; then
  warn "IAM role ${CW_ROLE_NAME} already exists — skipping."
else
  aws iam create-role \
    --role-name "${CW_ROLE_NAME}" \
    --assume-role-policy-document "${TRUST_POLICY}"
  aws iam put-role-policy \
    --role-name "${CW_ROLE_NAME}" \
    --policy-name "CloudTrailCloudWatchPolicy" \
    --policy-document "{
      \"Version\":\"2012-10-17\",
      \"Statement\":[{
        \"Effect\":\"Allow\",
        \"Action\":[\"logs:CreateLogStream\",\"logs:PutLogEvents\"],
        \"Resource\":\"${LOG_GROUP_ARN}\"
      }]
    }"
  success "IAM role created: ${CW_ROLE_NAME}"
fi
CW_ROLE_ARN=$(aws iam get-role \
  --role-name "${CW_ROLE_NAME}" \
  --query 'Role.Arn' --output text)

# ── 10. Create SNS Topic ──────────────────────────────────────
info "Creating SNS topic: ${SNS_TOPIC}..."
SNS_ARN=$(aws sns create-topic \
  --name "${SNS_TOPIC}" \
  --region "${REGION}" \
  --query 'TopicArn' --output text)
success "SNS topic created: ${SNS_ARN}"

# ── 11. Create CloudTrail Trail ───────────────────────────────
info "Creating CloudTrail trail: ${TRAIL_NAME}..."
if aws cloudtrail describe-trails \
     --trail-name-list "${TRAIL_NAME}" \
     --region "${REGION}" \
     --query 'trailList[0].TrailARN' \
     --output text 2>/dev/null | grep -q "arn:"; then
  warn "Trail ${TRAIL_NAME} already exists — skipping creation."
else
  TRAIL_ARN=$(aws cloudtrail create-trail \
    --name "${TRAIL_NAME}" \
    --s3-bucket-name "${BUCKET_NAME}" \
    --s3-key-prefix "cloudtrail" \
    --include-global-service-events \
    --is-multi-region-trail \
    --enable-log-file-validation \
    --cloud-watch-logs-log-group-arn "${LOG_GROUP_ARN}" \
    --cloud-watch-logs-role-arn "${CW_ROLE_ARN}" \
    --sns-topic-name "${SNS_TOPIC}" \
    --region "${REGION}" \
    --query 'TrailARN' --output text)
  success "Trail created: ${TRAIL_ARN}"
fi

# ── 12. Add Event Selectors ───────────────────────────────────
info "Configuring event selectors (management + data events)..."
aws cloudtrail put-event-selectors \
  --trail-name "${TRAIL_NAME}" \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {"Type":"AWS::S3::Object","Values":["arn:aws:s3:::"]},
        {"Type":"AWS::Lambda::Function","Values":["arn:aws:lambda"]}
      ]
    }
  ]' \
  --region "${REGION}"
success "Event selectors configured."

# ── 13. Enable Insight Selectors ─────────────────────────────
info "Enabling CloudTrail Insights..."
aws cloudtrail put-insight-selectors \
  --trail-name "${TRAIL_NAME}" \
  --insight-selectors '[
    {"InsightType":"ApiCallRateInsight"},
    {"InsightType":"ApiErrorRateInsight"}
  ]' \
  --region "${REGION}" || warn "Insights may not be available in free tier — skipping."

# ── 14. Start Logging ─────────────────────────────────────────
info "Starting CloudTrail logging..."
aws cloudtrail start-logging \
  --name "${TRAIL_NAME}" \
  --region "${REGION}"
success "Logging started."

# ── 15. Tag Resources ─────────────────────────────────────────
info "Tagging CloudTrail trail..."
TRAIL_ARN=$(aws cloudtrail describe-trails \
  --trail-name-list "${TRAIL_NAME}" \
  --region "${REGION}" \
  --query 'trailList[0].TrailARN' --output text)
aws cloudtrail add-tags \
  --resource-id "${TRAIL_ARN}" \
  --tags-list \
    Key=Project,Value=06-cloud-soc-canada \
    Key=Environment,Value=lab \
    Key=Region,Value=ca-central-1 \
  --region "${REGION}"

# ── 16. Verify Setup ──────────────────────────────────────────
info "Verifying CloudTrail configuration..."
aws cloudtrail describe-trails \
  --trail-name-list "${TRAIL_NAME}" \
  --region "${REGION}" \
  --output table

aws cloudtrail get-trail-status \
  --name "${TRAIL_NAME}" \
  --region "${REGION}" \
  --output table

# ── 17. Summary ───────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  Setup Complete — Resource ARNs"
echo "=============================================="
echo ""
success "S3 Bucket:       arn:aws:s3:::${BUCKET_NAME}"
success "CloudTrail ARN:  ${TRAIL_ARN}"
success "CloudWatch Group:${LOG_GROUP_ARN}"
success "CW Role ARN:     ${CW_ROLE_ARN}"
success "SNS Topic ARN:   ${SNS_ARN}"
echo ""
echo "Add these to your .env file:"
echo "  AWS_CLOUDTRAIL_BUCKET=${BUCKET_NAME}"
echo "  AWS_CLOUDTRAIL_TRAIL_NAME=${TRAIL_NAME}"
echo "  AWS_CLOUDTRAIL_LOG_GROUP=${LOG_GROUP}"
echo ""
success "CloudTrail setup complete for ca-central-1!"
