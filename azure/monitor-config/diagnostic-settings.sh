#!/usr/bin/env bash
# =============================================================
# diagnostic-settings.sh
# Configures Azure Monitor Diagnostic Settings for SOC lab
# Sends all logs to Log Analytics workspace (canadacentral)
# Usage: bash diagnostic-settings.sh
# Prereqs: az login, az account set --subscription <ID>
# =============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Config — populate from .env or set manually ───────────────
SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-}"
WORKSPACE_ID="${AZURE_LOG_ANALYTICS_WORKSPACE_ID:-}"
WORKSPACE_NAME="${AZURE_LOG_ANALYTICS_WORKSPACE_NAME:-soc-lab-workspace}"
RESOURCE_GROUP="${AZURE_SENTINEL_RESOURCE_GROUP:-soc-lab-rg}"
LOCATION="canadacentral"

[[ -z "${SUBSCRIPTION_ID}" ]] && error "AZURE_SUBSCRIPTION_ID not set"
[[ -z "${WORKSPACE_ID}" ]]    && error "AZURE_LOG_ANALYTICS_WORKSPACE_ID not set"

WORKSPACE_RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}"

echo ""
echo "=============================================="
echo "  SOC Lab — Azure Diagnostic Settings"
echo "  Location: canadacentral"
echo "=============================================="
echo ""

az account set --subscription "${SUBSCRIPTION_ID}"
success "Subscription set: ${SUBSCRIPTION_ID}"

# ── 1. Create Resource Group if not exists ────────────────────
info "Ensuring resource group ${RESOURCE_GROUP} exists in ${LOCATION}..."
az group create \
  --name "${RESOURCE_GROUP}" \
  --location "${LOCATION}" \
  --output none
success "Resource group ready: ${RESOURCE_GROUP}"

# ── 2. Create Log Analytics Workspace ────────────────────────
info "Creating/verifying Log Analytics workspace..."
EXISTING_WS=$(az monitor log-analytics workspace show \
  --resource-group "${RESOURCE_GROUP}" \
  --workspace-name "${WORKSPACE_NAME}" \
  --query id --output tsv 2>/dev/null || echo "")

if [[ -z "${EXISTING_WS}" ]]; then
  az monitor log-analytics workspace create \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${WORKSPACE_NAME}" \
    --location "${LOCATION}" \
    --sku PerGB2018 \
    --retention-time 90 \
    --output none
  success "Log Analytics workspace created: ${WORKSPACE_NAME}"
else
  warn "Workspace already exists: ${WORKSPACE_NAME}"
fi

WORKSPACE_RESOURCE_ID=$(az monitor log-analytics workspace show \
  --resource-group "${RESOURCE_GROUP}" \
  --workspace-name "${WORKSPACE_NAME}" \
  --query id --output tsv)

# ── 3. Enable Azure Activity Log Diagnostic Settings ─────────
info "Configuring Activity Log diagnostic settings..."
az monitor diagnostic-settings create \
  --name "soc-lab-activity-logs" \
  --resource "/subscriptions/${SUBSCRIPTION_ID}" \
  --workspace "${WORKSPACE_RESOURCE_ID}" \
  --logs '[
    {"category":"Administrative","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"Security","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"ServiceHealth","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"Alert","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"Recommendation","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"Policy","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"Autoscale","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"ResourceHealth","enabled":true,"retentionPolicy":{"enabled":true,"days":90}}
  ]' \
  --output none 2>/dev/null || warn "Activity log diagnostic settings may already exist."
success "Activity Log diagnostic settings configured."

# ── 4. Configure Azure AD Sign-In and Audit Logs ─────────────
info "Configuring Azure AD diagnostic settings..."
AAD_RESOURCE_ID="/tenants/${AZURE_TENANT_ID:-$(az account show --query tenantId -o tsv)}/providers/microsoft.aadiam"
az monitor diagnostic-settings create \
  --name "soc-lab-aad-logs" \
  --resource "${AAD_RESOURCE_ID}" \
  --workspace "${WORKSPACE_RESOURCE_ID}" \
  --logs '[
    {"category":"SignInLogs","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"AuditLogs","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"NonInteractiveUserSignInLogs","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"ServicePrincipalSignInLogs","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"ManagedIdentitySignInLogs","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"RiskyUsers","enabled":true,"retentionPolicy":{"enabled":true,"days":90}},
    {"category":"UserRiskEvents","enabled":true,"retentionPolicy":{"enabled":true,"days":90}}
  ]' \
  --output none 2>/dev/null || warn "AAD diagnostic settings require AAD P1/P2 or may already exist."
success "Azure AD diagnostic settings configured."

# ── 5. Enable Microsoft Sentinel on Workspace ─────────────────
info "Enabling Microsoft Sentinel on workspace..."
az security insights workspace create \
  --resource-group "${RESOURCE_GROUP}" \
  --workspace-name "${WORKSPACE_NAME}" \
  --output none 2>/dev/null \
  || az sentinel --help &>/dev/null \
  && info "Sentinel enable via: az sentinel onboarding-state create --resource-group ${RESOURCE_GROUP} --workspace-name ${WORKSPACE_NAME}" \
  || warn "Sentinel CLI extension not installed. Run: az extension add --name sentinel"

# ── 6. Configure Data Connectors ─────────────────────────────
info "Reminder: Enable these Sentinel Data Connectors manually in portal:"
echo "  • Azure Active Directory"
echo "  • Azure Activity"
echo "  • Microsoft Defender for Cloud"
echo "  • Azure Key Vault"
echo "  • Azure Kubernetes Service"
echo "  • Office 365 (if available)"

# ── 7. Set up Alert Email Action Group ───────────────────────
info "Creating Action Group for SOC alerts..."
az monitor action-group create \
  --resource-group "${RESOURCE_GROUP}" \
  --name "soc-lab-alerts" \
  --short-name "soc-alerts" \
  --output none 2>/dev/null || warn "Action group may already exist."
success "Action group created: soc-lab-alerts"

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  Diagnostic Settings Complete"
echo "=============================================="
echo ""
success "Workspace: ${WORKSPACE_NAME}"
success "Resource Group: ${RESOURCE_GROUP}"
success "Location: ${LOCATION}"
echo ""
echo "Add to your .env:"
echo "  AZURE_LOG_ANALYTICS_WORKSPACE_ID=$(az monitor log-analytics workspace show --resource-group ${RESOURCE_GROUP} --workspace-name ${WORKSPACE_NAME} --query customerId -o tsv 2>/dev/null || echo '<run script to get>')"
echo ""
success "Azure Monitor diagnostic settings complete!"
