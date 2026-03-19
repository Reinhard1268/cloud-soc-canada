#!/usr/bin/env python3
"""
aws-auto-remediate.py
Automated AWS remediation functions for SOC lab.
All actions require --auto-approve or interactive confirmation.
Every action is written to remediation-log.json.
"""

import os
import json
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

import boto3
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
log = logging.getLogger("aws-auto-remediate")

REGION   = os.getenv("AWS_DEFAULT_REGION", "ca-central-1")
AUDIT_LOG = Path("logs/remediation-log.json")


# ── Audit Trail ───────────────────────────────────────────────
def audit(action: str, target: str, details: dict, result: str):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "target":    target,
        "details":   details,
        "result":    result,
        "region":    REGION,
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    log.info(f"Audit: {action} on {target} → {result}")


def confirm_action(action: str, target: str, auto_approve: bool) -> bool:
    if auto_approve:
        return True
    return Confirm.ask(f"[yellow]Execute '{action}' on '{target}'?[/yellow]")


# ── 1. Revoke IAM Permissions ─────────────────────────────────
def revoke_iam_permissions(user: str, policy_arn: str, auto_approve: bool = False):
    """Detach an IAM managed policy from a user."""
    log.info(f"Revoking policy {policy_arn} from user {user}")
    if not confirm_action("detach-user-policy", user, auto_approve):
        log.info("Action cancelled.")
        return

    iam = boto3.client("iam", region_name=REGION)
    try:
        iam.detach_user_policy(UserName=user, PolicyArn=policy_arn)
        audit("revoke_iam_permissions", user, {"policy_arn": policy_arn}, "SUCCESS")
        log.info(f"Policy {policy_arn} detached from {user}")
    except Exception as e:
        audit("revoke_iam_permissions", user, {"policy_arn": policy_arn, "error": str(e)}, "FAILED")
        log.error(f"Failed to detach policy: {e}")
        raise


# ── 2. Disable Access Key ─────────────────────────────────────
def disable_access_key(user: str, key_id: str, auto_approve: bool = False):
    """Disable a compromised IAM access key."""
    log.info(f"Disabling access key {key_id} for user {user}")
    if not confirm_action("disable-access-key", user, auto_approve):
        log.info("Action cancelled.")
        return

    iam = boto3.client("iam", region_name=REGION)
    try:
        iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
        audit("disable_access_key", user, {"key_id": key_id}, "SUCCESS")
        log.info(f"Access key {key_id} disabled for {user}")
    except Exception as e:
        audit("disable_access_key", user, {"key_id": key_id, "error": str(e)}, "FAILED")
        log.error(f"Failed to disable access key: {e}")
        raise


# ── 3. Isolate EC2 Instance ───────────────────────────────────
def isolate_ec2_instance(instance_id: str, auto_approve: bool = False):
    """Apply a restrictive security group to isolate a compromised EC2 instance."""
    log.info(f"Isolating EC2 instance {instance_id}")
    if not confirm_action("isolate-ec2", instance_id, auto_approve):
        log.info("Action cancelled.")
        return

    ec2 = boto3.client("ec2", region_name=REGION)
    try:
        instance    = ec2.describe_instances(InstanceIds=[instance_id])
        vpc_id      = instance["Reservations"][0]["Instances"][0]["VpcId"]
        original_sgs = [sg["GroupId"] for sg in
                         instance["Reservations"][0]["Instances"][0]["SecurityGroups"]]

        # Create isolation security group (deny all traffic)
        try:
            sg = ec2.create_security_group(
                GroupName=f"ISOLATED-{instance_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                Description=f"Isolation SG for {instance_id} — SOC auto-remediation",
                VpcId=vpc_id,
            )
            isolation_sg_id = sg["GroupId"]
            log.info(f"Created isolation SG: {isolation_sg_id}")
        except Exception:
            existing = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [f"ISOLATED-{instance_id}*"]}]
            )
            isolation_sg_id = existing["SecurityGroups"][0]["GroupId"]
            log.info(f"Using existing isolation SG: {isolation_sg_id}")

        # Apply isolation SG, removing all others
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id],
        )
        audit("isolate_ec2_instance", instance_id,
              {"isolation_sg": isolation_sg_id, "original_sgs": original_sgs}, "SUCCESS")
        log.info(f"Instance {instance_id} isolated with SG {isolation_sg_id}")
        log.warning(f"Original SGs [{', '.join(original_sgs)}] removed. Restore manually after investigation.")
    except Exception as e:
        audit("isolate_ec2_instance", instance_id, {"error": str(e)}, "FAILED")
        log.error(f"Failed to isolate instance: {e}")
        raise


# ── 4. Block IP in Network ACL ────────────────────────────────
def block_ip_in_nacl(vpc_id: str, ip: str, auto_approve: bool = False):
    """Add a DENY rule to the default Network ACL for a VPC to block an IP."""
    log.info(f"Blocking IP {ip} in VPC {vpc_id} NACL")
    if not confirm_action("block-ip-nacl", ip, auto_approve):
        log.info("Action cancelled.")
        return

    ec2 = boto3.client("ec2", region_name=REGION)
    try:
        nacls = ec2.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                     {"Name": "default",    "Values": ["true"]}]
        )
        nacl_id = nacls["NetworkAcls"][0]["NetworkAclId"]

        # Find an available rule number (100–200 reserved for SOC blocks)
        existing_rules = [e["RuleNumber"] for e in nacls["NetworkAcls"][0]["Entries"]
                          if 100 <= e["RuleNumber"] <= 200]
        rule_number    = max(existing_rules, default=99) + 1
        if rule_number > 200:
            log.error("NACL rule number range 100-200 exhausted. Clean up old rules.")
            return

        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=rule_number,
            Protocol="-1",
            RuleAction="deny",
            Egress=False,
            CidrBlock=f"{ip}/32",
        )
        audit("block_ip_in_nacl", ip,
              {"vpc_id": vpc_id, "nacl_id": nacl_id, "rule_number": rule_number}, "SUCCESS")
        log.info(f"IP {ip} blocked in NACL {nacl_id} (rule #{rule_number})")
    except Exception as e:
        audit("block_ip_in_nacl", ip, {"vpc_id": vpc_id, "error": str(e)}, "FAILED")
        log.error(f"Failed to block IP in NACL: {e}")
        raise


# ── 5. Delete Unauthorized IAM User ──────────────────────────
def delete_unauthorized_user(username: str, auto_approve: bool = False):
    """Remove an unauthorised IAM user and all associated resources."""
    log.info(f"Deleting unauthorized IAM user: {username}")
    if not confirm_action("delete-iam-user", username, auto_approve):
        log.info("Action cancelled.")
        return

    iam = boto3.client("iam", region_name=REGION)
    deleted_items = []
    try:
        # Detach all managed policies
        policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for p in policies:
            iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"])
            deleted_items.append(f"policy:{p['PolicyArn']}")

        # Delete inline policies
        inline = iam.list_user_policies(UserName=username)["PolicyNames"]
        for p in inline:
            iam.delete_user_policy(UserName=username, PolicyName=p)
            deleted_items.append(f"inline-policy:{p}")

        # Disable + delete access keys
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for k in keys:
            iam.update_access_key(UserName=username, AccessKeyId=k["AccessKeyId"], Status="Inactive")
            iam.delete_access_key(UserName=username, AccessKeyId=k["AccessKeyId"])
            deleted_items.append(f"access-key:{k['AccessKeyId']}")

        # Delete login profile (console access)
        try:
            iam.delete_login_profile(UserName=username)
            deleted_items.append("login-profile")
        except iam.exceptions.NoSuchEntityException:
            pass

        # Remove from groups
        groups = iam.list_groups_for_user(UserName=username)["Groups"]
        for g in groups:
            iam.remove_user_from_group(GroupName=g["GroupName"], UserName=username)
            deleted_items.append(f"group:{g['GroupName']}")

        # Delete MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        for d in mfa_devices:
            iam.deactivate_mfa_device(UserName=username, SerialNumber=d["SerialNumber"])
            iam.delete_virtual_mfa_device(SerialNumber=d["SerialNumber"])
            deleted_items.append(f"mfa:{d['SerialNumber']}")

        # Finally delete the user
        iam.delete_user(UserName=username)
        audit("delete_unauthorized_user", username,
              {"deleted_items": deleted_items}, "SUCCESS")
        log.info(f"User {username} deleted. Cleaned up: {deleted_items}")
    except Exception as e:
        audit("delete_unauthorized_user", username,
              {"deleted_items": deleted_items, "error": str(e)}, "FAILED")
        log.error(f"Failed to delete user {username}: {e}")
        raise


# ── CLI Entry Point ───────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="AWS Auto-Remediation — SOC Lab")
    parser.add_argument("--action", required=True, choices=[
        "revoke-iam-permissions",
        "disable-access-key",
        "isolate-ec2",
        "block-ip-nacl",
        "delete-unauthorized-user",
    ])
    parser.add_argument("--user",         help="IAM username")
    parser.add_argument("--policy-arn",   help="IAM policy ARN")
    parser.add_argument("--key-id",       help="IAM access key ID")
    parser.add_argument("--instance-id",  help="EC2 instance ID")
    parser.add_argument("--vpc-id",       help="VPC ID for NACL block")
    parser.add_argument("--ip",           help="IP address to block")
    parser.add_argument("--auto-approve", action="store_true",
                        help="Skip interactive confirmation prompts")
    args = parser.parse_args()

    console.rule("[bold red]AWS Auto-Remediation[/bold red]")
    log.warning("⚠️  All actions are IRREVERSIBLE without manual rollback. Review audit log.")

    if args.action == "revoke-iam-permissions":
        assert args.user and args.policy_arn, "--user and --policy-arn required"
        revoke_iam_permissions(args.user, args.policy_arn, args.auto_approve)

    elif args.action == "disable-access-key":
        assert args.user and args.key_id, "--user and --key-id required"
        disable_access_key(args.user, args.key_id, args.auto_approve)

    elif args.action == "isolate-ec2":
        assert args.instance_id, "--instance-id required"
        isolate_ec2_instance(args.instance_id, args.auto_approve)

    elif args.action == "block-ip-nacl":
        assert args.vpc_id and args.ip, "--vpc-id and --ip required"
        block_ip_in_nacl(args.vpc_id, args.ip, args.auto_approve)

    elif args.action == "delete-unauthorized-user":
        assert args.user, "--user required"
        delete_unauthorized_user(args.user, args.auto_approve)

    log.info(f"Audit trail written to: {AUDIT_LOG}")


if __name__ == "__main__":
    main()
