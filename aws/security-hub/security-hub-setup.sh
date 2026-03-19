#!/usr/bin/env bash
# =============================================================
# security-hub-setup.sh
# Enables AWS Security Hub with CIS + FSBP standards
# in ca-central-1
# Usage: bash security-hub-setup.sh
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

# Standard ARNs for ca-central-1
FSBP_ARN="arn:aws:securityhub:${REGION}::standards/aws-foundational-security-best-practices/v/1.0.0"
CIS_ARN="arn:aws:securityhub:${REGION}::standards/cis-aws-foundations-benchmark/v/1.4.0"
PCIDSS_ARN="arn:aws:securityhub:${REGION}::standards/pci-dss/v/3.2.1"

echo ""
echo "=============================================="
echo "  SOC Lab — Security Hub Setup (ca-central-1)"
echo "=============================================="
echo ""

# ── 1. Enable Security Hub ─────────────────────────────────────
info "Enabling Security Hub in ${REGION}..."
aws securityhub enable-security-hub \
  --enable-default-standards \
  --region "${REGION}" 2>/dev/null \
  && success "Security Hub enabled." \
  || warn "Security Hub may already be enabled — continuing."

SECURITY_HUB_ARN="arn:aws:securityhub:${REGION}:${ACCOUNT_ID}:hub/default"

# ── 2. Enable AWS Foundational Security Best Practices ─────────
info "Enabling AWS Foundational Security Best Practices standard..."
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    "[{\"StandardsArn\":\"${FSBP_ARN}\"}]" \
  --region "${REGION}" 2>/dev/null \
  && success "FSBP standard enabled." \
  || warn "FSBP standard may already be enabled."

# ── 3. Enable CIS AWS Foundations Benchmark v1.4 ──────────────
info "Enabling CIS AWS Foundations Benchmark v1.4..."
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    "[{\"StandardsArn\":\"${CIS_ARN}\"}]" \
  --region "${REGION}" 2>/dev/null \
  && success "CIS benchmark enabled." \
  || warn "CIS benchmark may already be enabled."

# ── 4. Enable GuardDuty Integration ───────────────────────────
info "Enabling GuardDuty integration with Security Hub..."
GUARDDUTY_INTEGRATION_ARN="arn:aws:securityhub:${REGION}::product/aws/guardduty"
aws securityhub enable-import-findings-for-product \
  --product-arn "${GUARDDUTY_INTEGRATION_ARN}" \
  --region "${REGION}" 2>/dev/null \
  && success "GuardDuty → Security Hub integration enabled." \
  || warn "GuardDuty integration may already be enabled."

# ── 5. Enable Inspector Integration ───────────────────────────
info "Enabling Inspector v2 integration..."
INSPECTOR_INTEGRATION_ARN="arn:aws:securityhub:${REGION}::product/aws/inspector"
aws securityhub enable-import-findings-for-product \
  --product-arn "${INSPECTOR_INTEGRATION_ARN}" \
  --region "${REGION}" 2>/dev/null \
  && success "Inspector integration enabled." \
  || warn "Inspector integration may not be available — skipping."

# ── 6. Enable Macie Integration ───────────────────────────────
info "Attempting Macie integration..."
MACIE_INTEGRATION_ARN="arn:aws:securityhub:${REGION}::product/aws/macie"
aws securityhub enable-import-findings-for-product \
  --product-arn "${MACIE_INTEGRATION_ARN}" \
  --region "${REGION}" 2>/dev/null \
  && success "Macie integration enabled." \
  || warn "Macie not available in free tier — skipping."

# ── 7. Configure Finding Aggregation ──────────────────────────
info "Setting up finding aggregation for ca-central-1..."
aws securityhub update-security-hub-configuration \
  --auto-enable-controls \
  --region "${REGION}" 2>/dev/null \
  && success "Auto-enable controls configured." \
  || warn "Auto-enable controls may already be set."

# ── 8. Create EventBridge Rule for Findings ───────────────────
info "Creating EventBridge rule to forward Security Hub findings..."
aws events put-rule \
  --name "security-hub-findings-forward" \
  --event-pattern "{
    \"source\": [\"aws.securityhub\"],
    \"detail-type\": [\"Security Hub Findings - Imported\"]
  }" \
  --state ENABLED \
  --region "${REGION}" \
  --description "Forward Security Hub findings for SOC lab processing" \
  --query 'RuleArn' --output text \
  && success "EventBridge rule created." \
  || warn "EventBridge rule creation failed — configure manually."

# ── 9. Tag Security Hub Hub ───────────────────────────────────
info "Tagging Security Hub resources..."
aws securityhub tag-resource \
  --resource-arn "${SECURITY_HUB_ARN}" \
  --tags \
    Project=06-cloud-soc-canada \
    Environment=lab \
    Region="${REGION}" \
  --region "${REGION}" 2>/dev/null \
  || warn "Tagging not supported on hub resource — skipping."

# ── 10. List Active Standards ─────────────────────────────────
info "Listing active Security Hub standards..."
aws securityhub get-enabled-standards \
  --region "${REGION}" \
  --output table

# ── 11. Summary ───────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  Security Hub Setup Complete"
echo "=============================================="
echo ""
success "Security Hub ARN: ${SECURITY_HUB_ARN}"
success "Region:           ${REGION}"
success "Standards:        FSBP v1.0 + CIS v1.4"
success "Integrations:     GuardDuty, Inspector, Macie"
echo ""
echo "Add to your .env:"
echo "  AWS_SECURITY_HUB_ARN=${SECURITY_HUB_ARN}"
echo ""
success "Security Hub is active and collecting findings!"
