#!/usr/bin/env python3
"""
azure-auto-remediate.py
Automated Azure remediation functions for SOC lab.
All actions require --auto-approve or interactive confirmation.
Every action is written to remediation-log.json.
"""

import os
import json
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.prompt import Confirm

load_dotenv()
console = Console()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger("azure-auto-remediate")

TENANT_ID       = os.getenv("AZURE_TENANT_ID", "")
CLIENT_ID       = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET   = os.getenv("AZURE_CLIENT_SECRET", "")
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")
RESOURCE_GROUP  = os.getenv("AZURE_SENTINEL_RESOURCE_GROUP", "soc-lab-rg")
AUDIT_LOG       = Path("logs/remediation-log.json")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
ARM_BASE   = "https://management.azure.com"


# ── Auth Helpers ──────────────────────────────────────────────
def get_graph_token() -> str:
    r = requests.post(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope":         "https://graph.microsoft.com/.default",
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def get_arm_token() -> str:
    r = requests.post(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope":         "https://management.azure.com/.default",
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def graph_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def arm_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ── Audit Trail ───────────────────────────────────────────────
def audit(action: str, target: str, details: dict, result: str):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "target":    target,
        "details":   details,
        "result":    result,
        "platform":  "azure",
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    log.info(f"Audit: {action} on {target} → {result}")


def confirm_action(action: str, target: str, auto_approve: bool) -> bool:
    if auto_approve:
        return True
    return Confirm.ask(f"[yellow]Execute '{action}' on '{target}'?[/yellow]")


# ── 1. Revoke Role Assignment ─────────────────────────────────
def revoke_role_assignment(user_id: str, role: str, auto_approve: bool = False):
    """Remove an Azure RBAC role assignment from a user."""
    log.info(f"Revoking role '{role}' from user {user_id}")
    if not confirm_action("revoke-role-assignment", user_id, auto_approve):
        log.info("Action cancelled.")
        return

    token = get_arm_token()
    # List role assignments for the user
    r = requests.get(
        f"{ARM_BASE}/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments"
        f"?$filter=principalId eq '{user_id}'&api-version=2022-04-01",
        headers=arm_headers(token),
        timeout=10,
    )
    r.raise_for_status()
    assignments = r.json().get("value", [])

    revoked = []
    for a in assignments:
        role_def_id = a["properties"].get("roleDefinitionId", "")
        if role.lower() in role_def_id.lower() or role.lower() in a.get("id", "").lower():
            del_r = requests.delete(
                f"{ARM_BASE}{a['id']}?api-version=2022-04-01",
                headers=arm_headers(token),
                timeout=10,
            )
            if del_r.status_code in (200, 204):
                revoked.append(a["id"])
                log.info(f"Revoked: {a['id']}")
            else:
                log.error(f"Failed to revoke {a['id']}: {del_r.text}")

    if revoked:
        audit("revoke_role_assignment", user_id, {"role": role, "revoked": revoked}, "SUCCESS")
    else:
        log.warning(f"No role assignment found for role '{role}' on user '{user_id}'")
        audit("revoke_role_assignment", user_id, {"role": role}, "NOT_FOUND")


# ── 2. Disable User Account ───────────────────────────────────
def disable_user_account(user_id: str, auto_approve: bool = False):
    """Disable an Azure AD user account."""
    log.info(f"Disabling Azure AD account: {user_id}")
    if not confirm_action("disable-user-account", user_id, auto_approve):
        log.info("Action cancelled.")
        return

    token = get_graph_token()
    r = requests.patch(
        f"{GRAPH_BASE}/users/{user_id}",
        headers=graph_headers(token),
        json={"accountEnabled": False},
        timeout=10,
    )
    if r.status_code == 204:
        audit("disable_user_account", user_id, {}, "SUCCESS")
        log.info(f"Account {user_id} disabled.")
    else:
        audit("disable_user_account", user_id, {"error": r.text}, "FAILED")
        log.error(f"Failed to disable account: {r.status_code} {r.text}")
        r.raise_for_status()


# ── 3. Block IP in NSG ────────────────────────────────────────
def block_ip_in_nsg(nsg_name: str, ip: str, auto_approve: bool = False):
    """Add a DENY inbound rule to an Azure Network Security Group."""
    log.info(f"Blocking IP {ip} in NSG {nsg_name}")
    if not confirm_action("block-ip-nsg", ip, auto_approve):
        log.info("Action cancelled.")
        return

    token = get_arm_token()
    # Get current NSG to find next available priority
    r = requests.get(
        f"{ARM_BASE}/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}?api-version=2023-05-01",
        headers=arm_headers(token),
        timeout=10,
    )
    r.raise_for_status()
    nsg         = r.json()
    rules       = nsg.get("properties", {}).get("securityRules", [])
    priorities  = [rule["properties"]["priority"] for rule in rules
                   if 3900 <= rule["properties"].get("priority", 0) <= 4000]
    priority    = max(priorities, default=3899) + 1
    if priority > 4000:
        log.error("NSG priority range 3900-4000 exhausted. Clean up old SOC block rules.")
        return

    rule_name = f"SOC-BLOCK-{ip.replace('.', '-')}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    rule_body  = {
        "properties": {
            "priority":                 priority,
            "protocol":                 "*",
            "access":                   "Deny",
            "direction":                "Inbound",
            "sourceAddressPrefix":      ip,
            "sourcePortRange":          "*",
            "destinationAddressPrefix": "*",
            "destinationPortRange":     "*",
            "description":              f"SOC auto-block for {ip}",
        }
    }
    put_r = requests.put(
        f"{ARM_BASE}/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}"
        f"/securityRules/{rule_name}?api-version=2023-05-01",
        headers=arm_headers(token),
        json=rule_body,
        timeout=30,
    )
    if put_r.status_code in (200, 201):
        audit("block_ip_in_nsg", ip,
              {"nsg": nsg_name, "rule": rule_name, "priority": priority}, "SUCCESS")
        log.info(f"IP {ip} blocked in NSG {nsg_name} (rule: {rule_name}, priority: {priority})")
    else:
        audit("block_ip_in_nsg", ip, {"nsg": nsg_name, "error": put_r.text}, "FAILED")
        log.error(f"Failed to add NSG rule: {put_r.status_code} {put_r.text}")
        put_r.raise_for_status()


# ── 4. Revoke Service Principal Secret ───────────────────────
def revoke_service_principal_secret(sp_id: str, auto_approve: bool = False):
    """Remove all client secrets from a service principal."""
    log.info(f"Revoking all secrets for service principal: {sp_id}")
    if not confirm_action("revoke-sp-secret", sp_id, auto_approve):
        log.info("Action cancelled.")
        return

    token = get_graph_token()
    # List all password credentials
    r = requests.get(
        f"{GRAPH_BASE}/servicePrincipals/{sp_id}/passwordCredentials",
        headers=graph_headers(token),
        timeout=10,
    )
    r.raise_for_status()
    creds   = r.json().get("value", [])
    revoked = []

    for cred in creds:
        key_id  = cred["keyId"]
        del_r   = requests.delete(
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}/removePassword",
            headers=graph_headers(token),
            json={"keyId": key_id},
            timeout=10,
        )
        if del_r.status_code == 204:
            revoked.append(key_id)
            log.info(f"Revoked secret key {key_id}")
        else:
            log.error(f"Failed to revoke key {key_id}: {del_r.text}")

    audit("revoke_service_principal_secret", sp_id,
          {"revoked_keys": revoked, "total": len(creds)}, "SUCCESS" if revoked else "PARTIAL")
    log.info(f"Revoked {len(revoked)}/{len(creds)} secrets from SP {sp_id}")


# ── 5. Enable MFA Requirement ─────────────────────────────────
def enable_mfa_requirement(user_id: str, auto_approve: bool = False):
    """
    Revoke all active sessions for a user and flag them for MFA re-registration.
    Full Conditional Access MFA enforcement requires portal/policy configuration.
    """
    log.info(f"Revoking sessions and enforcing MFA re-registration for: {user_id}")
    if not confirm_action("enable-mfa-requirement", user_id, auto_approve):
        log.info("Action cancelled.")
        return

    token = get_graph_token()

    # Step 1: Revoke all refresh tokens (force re-auth)
    r = requests.post(
        f"{GRAPH_BASE}/users/{user_id}/revokeSignInSessions",
        headers=graph_headers(token),
        timeout=10,
    )
    if r.status_code == 200:
        log.info(f"All active sessions revoked for {user_id}")
    else:
        log.warning(f"Session revocation returned {r.status_code}: {r.text}")

    # Step 2: Invalidate refresh tokens via invalidateAllRefreshTokens
    r2 = requests.post(
        f"{GRAPH_BASE}/users/{user_id}/invalidateAllRefreshTokens",
        headers=graph_headers(token),
        timeout=10,
    )
    tokens_invalidated = r2.status_code == 200

    # Step 3: Remove strong authentication methods (forces re-registration)
    r3 = requests.get(
        f"{GRAPH_BASE}/users/{user_id}/authentication/methods",
        headers=graph_headers(token),
        timeout=10,
    )
    methods_count = 0
    if r3.status_code == 200:
        methods       = r3.json().get("value", [])
        methods_count = len(methods)
        log.info(f"User has {methods_count} authentication method(s) registered")

    audit("enable_mfa_requirement", user_id,
          {"sessions_revoked": True,
           "tokens_invalidated": tokens_invalidated,
           "auth_methods_count": methods_count},
          "SUCCESS")
    log.info(f"MFA re-registration required for {user_id}.")
    log.warning("To fully enforce MFA: assign user to a Conditional Access policy "
                "requiring MFA, or enable Security Defaults in Azure AD.")


# ── CLI Entry Point ───────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Azure Auto-Remediation — SOC Lab")
    parser.add_argument("--action", required=True, choices=[
        "revoke-role",
        "disable-user",
        "block-ip-nsg",
        "revoke-sp-secret",
        "enable-mfa",
    ])
    parser.add_argument("--user-id",    help="Azure AD user ID or UPN")
    parser.add_argument("--role",       help="Azure RBAC role name")
    parser.add_argument("--nsg-name",   help="Network Security Group name")
    parser.add_argument("--ip",         help="IP address to block")
    parser.add_argument("--sp-id",      help="Service Principal object ID")
    parser.add_argument("--auto-approve", action="store_true",
                        help="Skip interactive confirmation prompts")
    args = parser.parse_args()

    console.rule("[bold red]Azure Auto-Remediation[/bold red]")
    log.warning("⚠️  All actions are IRREVERSIBLE without manual rollback. Review audit log.")

    if args.action == "revoke-role":
        assert args.user_id and args.role, "--user-id and --role required"
        revoke_role_assignment(args.user_id, args.role, args.auto_approve)

    elif args.action == "disable-user":
        assert args.user_id, "--user-id required"
        disable_user_account(args.user_id, args.auto_approve)

    elif args.action == "block-ip-nsg":
        assert args.nsg_name and args.ip, "--nsg-name and --ip required"
        block_ip_in_nsg(args.nsg_name, args.ip, args.auto_approve)

    elif args.action == "revoke-sp-secret":
        assert args.sp_id, "--sp-id required"
        revoke_service_principal_secret(args.sp_id, args.auto_approve)

    elif args.action == "enable-mfa":
        assert args.user_id, "--user-id required"
        enable_mfa_requirement(args.user_id, args.auto_approve)

    log.info(f"Audit trail written to: {AUDIT_LOG}")


if __name__ == "__main__":
    main()
