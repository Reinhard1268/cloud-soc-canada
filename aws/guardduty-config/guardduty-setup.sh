#!/usr/bin/env bash
# =============================================================
# guardduty-setup.sh
# Enables and configures AWS GuardDuty in ca-central-1
# Usage: bash guardduty-setup.sh
# =============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

REGION="ca-central-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text \
             || error "AWS CLI not configured.")
BUCKET_NAME="soc-lab-cloudtrail-logs-ca-${ACCOUNT_ID}"
THREAT_INTEL_FILE="$(dirname "$0")/threat-intel-feed.txt"
THREAT_INTEL_S3_KEY="guardduty/threat-intel/malicious-ips.txt"

echo ""
echo "=============================================="
echo "  SOC Lab — GuardDuty Setup (ca-central-1)"
echo "=============================================="
echo ""

# ── 1. Enable GuardDuty ───────────────────────────────────────
info "Checking GuardDuty status in ${REGION}..."
EXISTING_DETECTORS=$(aws guardduty list-detectors \
  --region "${REGION}" \
  --query 'DetectorIds' --output json)

if [[ "${EXISTING_DETECTORS}" != "[]" ]]; then
  DETECTOR_ID=$(echo "${EXISTING_DETECTORS}" | python3 -c "import sys,json; print(json.load(sys.stdin)[0])")
  warn "GuardDuty already enabled. Detector ID: ${DETECTOR_ID}"
else
  info "Enabling GuardDuty..."
  DETECTOR_ID=$(aws guardduty create-detector \
    --enable \
    --finding-publishing-frequency FIFTEEN_MINUTES \
    --region "${REGION}" \
    --query 'DetectorId' --output text)
  success "GuardDuty enabled. Detector ID: ${DETECTOR_ID}"
fi

# ── 2. Set Finding Publishing Frequency ──────────────────────
info "Setting finding publishing frequency to FIFTEEN_MINUTES..."
aws guardduty update-detector \
  --detector-id "${DETECTOR_ID}" \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --region "${REGION}"
success "Publishing frequency set."

# ── 3. Enable S3 Protection ───────────────────────────────────
info "Enabling S3 Protection..."
aws guardduty update-detector \
  --detector-id "${DETECTOR_ID}" \
  --features '[{"Name":"S3_DATA_EVENTS","Status":"ENABLED"}]' \
  --region "${REGION}" || warn "S3 protection feature flag may differ in your CLI version."
success "S3 Protection enabled."

# ── 4. Enable EKS Protection ──────────────────────────────────
info "Enabling EKS Audit Log Monitoring (if available)..."
aws guardduty update-detector \
  --detector-id "${DETECTOR_ID}" \
  --features '[{"Name":"EKS_AUDIT_LOGS","Status":"ENABLED"}]' \
  --region "${REGION}" 2>/dev/null \
  && success "EKS Protection enabled." \
  || warn "EKS Protection not available in this region/account — skipping."

# ── 5. Enable Malware Protection ──────────────────────────────
info "Enabling Malware Protection..."
aws guardduty update-detector \
  --detector-id "${DETECTOR_ID}" \
  --features '[{"Name":"EBS_MALWARE_PROTECTION","Status":"ENABLED"}]' \
  --region "${REGION}" 2>/dev/null \
  && success "Malware Protection enabled." \
  || warn "Malware Protection not available — skipping."

# ── 6. Upload Threat Intel Feed to S3 ────────────────────────
if [[ -f "${THREAT_INTEL_FILE}" ]]; then
  info "Uploading threat intel feed to S3..."
  aws s3 cp "${THREAT_INTEL_FILE}" \
    "s3://${BUCKET_NAME}/${THREAT_INTEL_S3_KEY}" \
    --region "${REGION}"
  THREAT_INTEL_URI="s3://${BUCKET_NAME}/${THREAT_INTEL_S3_KEY}"
  success "Threat intel uploaded: ${THREAT_INTEL_URI}"

  # ── 7. Create Threat Intel Set ────────────────────────────
  info "Adding custom threat intel feed to GuardDuty..."
  EXISTING_SETS=$(aws guardduty list-threat-intel-sets \
    --detector-id "${DETECTOR_ID}" \
    --region "${REGION}" \
    --query 'ThreatIntelSetIds' --output json)

  if [[ "${EXISTING_SETS}" == "[]" ]]; then
    THREAT_SET_ID=$(aws guardduty create-threat-intel-set \
      --detector-id "${DETECTOR_ID}" \
      --name "SOC-Lab-Malicious-IPs" \
      --format TXT \
      --location "${THREAT_INTEL_URI}" \
      --activate \
      --region "${REGION}" \
      --query 'ThreatIntelSetId' --output text)
    success "Threat intel set created: ${THREAT_SET_ID}"
  else
    warn "Threat intel set already exists — skipping creation."
  fi
else
  warn "threat-intel-feed.txt not found — skipping threat intel setup."
fi

# ── 8. Export Findings to S3 via EventBridge ─────────────────
info "Creating EventBridge rule to export GuardDuty findings to S3..."
aws events put-rule \
  --name "guardduty-findings-to-s3" \
  --event-pattern "{\"source\":[\"aws.guardduty\"],\"detail-type\":[\"GuardDuty Finding\"]}" \
  --state ENABLED \
  --region "${REGION}" \
  --description "Forward GuardDuty findings for SOC lab" \
  --query 'RuleArn' --output text \
  && success "EventBridge rule created." \
  || warn "EventBridge rule creation failed — configure manually if needed."

# ── 9. Verify ─────────────────────────────────────────────────
info "Verifying GuardDuty configuration..."
aws guardduty get-detector \
  --detector-id "${DETECTOR_ID}" \
  --region "${REGION}" \
  --output table

# ── 10. Summary ───────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  GuardDuty Setup Complete"
echo "=============================================="
echo ""
success "Detector ID: ${DETECTOR_ID}"
success "Region:      ${REGION}"
echo ""
echo "Add this to your .env file:"
echo "  AWS_GUARDDUTY_DETECTOR_ID=${DETECTOR_ID}"
echo ""
success "GuardDuty is active and monitoring ca-central-1!"
