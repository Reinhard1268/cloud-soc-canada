#!/usr/bin/env python3
"""
security-hub-to-elastic.py
Polls AWS Security Hub findings, normalises to ECS format,
indexes to Elasticsearch, and generates compliance summary reports.
"""

import os
import json
import time
import hashlib
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

import boto3
from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

load_dotenv()
console = Console()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger("securityhub-to-elastic")

REGION        = os.getenv("AWS_DEFAULT_REGION", "ca-central-1")
ELASTIC_URL   = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER  = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS  = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_INDEX = os.getenv("ELASTIC_SECURITYHUB_INDEX", "aws-security-hub-findings")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_MINUTES", 5)) * 60
STATE_FILE    = Path("logs/securityhub_state.json")
REPORT_DIR    = Path("compliance/cis-benchmarks")


def load_state() -> dict:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"processed_ids": []}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_es() -> Elasticsearch:
    return Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USER, ELASTIC_PASS),
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=30,
    )


def severity_label(sev: str) -> str:
    mapping = {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "INFORMATIONAL": "info",
    }
    return mapping.get(sev.upper(), "info")


def normalise_finding(finding: dict) -> dict:
    sev         = finding.get("Severity", {})
    sev_label   = finding.get("Severity", {}).get("Label", "INFORMATIONAL")
    compliance  = finding.get("Compliance", {})
    resources   = finding.get("Resources", [])
    generator   = finding.get("GeneratorId", "")
    account_id  = finding.get("AwsAccountId", "")
    finding_id  = finding.get("Id", "")

    doc_id = hashlib.sha256(finding_id.encode()).hexdigest()

    return {
        "@timestamp": finding.get("UpdatedAt", datetime.now(timezone.utc).isoformat()),
        "event": {
            "id":       finding_id,
            "kind":     "alert",
            "category": ["compliance"],
            "type":     ["info"],
            "action":   finding.get("Title", ""),
            "outcome":  "success",
            "dataset":  "aws.securityhub",
            "module":   "aws",
        },
        "cloud": {
            "provider": "aws",
            "region":   finding.get("Region", REGION),
            "account":  {"id": account_id},
        },
        "aws": {
            "security_hub": {
                "finding_id":        finding_id,
                "title":             finding.get("Title"),
                "description":       finding.get("Description"),
                "severity_label":    sev_label,
                "severity_score":    sev.get("Normalized", 0),
                "compliance_status": compliance.get("Status", "UNKNOWN"),
                "compliance_related_requirements": compliance.get("RelatedRequirements", []),
                "generator_id":      generator,
                "product_arn":       finding.get("ProductArn"),
                "workflow_status":   finding.get("Workflow", {}).get("Status", "NEW"),
                "record_state":      finding.get("RecordState", "ACTIVE"),
                "resources":         resources,
                "remediation":       finding.get("Remediation", {}),
                "created_at":        finding.get("CreatedAt"),
                "updated_at":        finding.get("UpdatedAt"),
            }
        },
        "labels": {
            "severity":          severity_label(sev_label),
            "compliance_status": compliance.get("Status", "UNKNOWN"),
            "standard":          generator.split("/")[0] if "/" in generator else generator,
        },
        "tags": ["security-hub", "aws", "ca-central-1", severity_label(sev_label)],
        "_doc_id": doc_id,
    }


def fetch_findings(sh_client, state: dict) -> list:
    processed  = set(state.get("processed_ids", []))
    all_findings = []
    paginator = sh_client.get_paginator("get_findings")
    pages = paginator.paginate(
        Filters={
            "SeverityLabel": [
                {"Value": "CRITICAL", "Comparison": "EQUALS"},
                {"Value": "HIGH",     "Comparison": "EQUALS"},
                {"Value": "MEDIUM",   "Comparison": "EQUALS"},
            ],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [
                {"Value": "NEW",        "Comparison": "EQUALS"},
                {"Value": "NOTIFIED",   "Comparison": "EQUALS"},
            ],
        },
        SortCriteria=[{"Field": "UpdatedAt", "SortOrder": "desc"}],
        MaxResults=100,
    )
    for page in pages:
        for f in page.get("Findings", []):
            if f.get("Id") not in processed:
                all_findings.append(f)
    log.info(f"Fetched {len(all_findings)} new Security Hub finding(s).")
    return all_findings


def generate_compliance_summary(findings: list) -> dict:
    summary = {
        "total":   len(findings),
        "PASSED":  0,
        "FAILED":  0,
        "WARNING": 0,
        "UNKNOWN": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
        "by_standard": {},
    }
    for f in findings:
        status  = f.get("Compliance", {}).get("Status", "UNKNOWN")
        sev     = f.get("Severity", {}).get("Label", "INFORMATIONAL")
        gen     = f.get("GeneratorId", "unknown")
        standard = gen.split("/")[0] if "/" in gen else gen

        summary[status] = summary.get(status, 0) + 1
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
        summary["by_standard"][standard] = summary["by_standard"].get(standard, 0) + 1

    total_checked = summary["PASSED"] + summary["FAILED"]
    summary["compliance_pct"] = (
        round(summary["PASSED"] / total_checked * 100, 1) if total_checked > 0 else 0
    )
    return summary


def print_summary_table(summary: dict):
    table = Table(title="Security Hub Compliance Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value",  style="green")
    table.add_row("Total Findings",    str(summary["total"]))
    table.add_row("PASSED",            str(summary["PASSED"]))
    table.add_row("FAILED",            str(summary["FAILED"]))
    table.add_row("WARNING",           str(summary["WARNING"]))
    table.add_row("Compliance %",      f"{summary['compliance_pct']}%")
    table.add_row("CRITICAL findings", str(summary["by_severity"]["CRITICAL"]))
    table.add_row("HIGH findings",     str(summary["by_severity"]["HIGH"]))
    console.print(table)


def run_poll(es: Elasticsearch, dry_run: bool = False):
    log.info("─" * 60)
    log.info(f"[Poll] {datetime.now(timezone.utc).isoformat()}")

    state     = load_state()
    sh_client = boto3.client("securityhub", region_name=REGION)
    findings  = fetch_findings(sh_client, state)

    if not findings:
        log.info("No new Security Hub findings.")
        return

    summary = generate_compliance_summary(findings)
    print_summary_table(summary)

    ecs_docs = [normalise_finding(f) for f in findings]
    actions  = []
    for doc in ecs_docs:
        doc_id = doc.pop("_doc_id", None)
        actions.append({"_index": ELASTIC_INDEX, "_id": doc_id, "_source": doc})
        state["processed_ids"].append(doc.get("aws", {})
                                         .get("security_hub", {})
                                         .get("finding_id", ""))

    if not dry_run and actions:
        ok, errors = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
        log.info(f"Indexed {ok} findings | Errors: {len(errors) if isinstance(errors, list) else errors}")
    elif dry_run:
        log.info(f"[DRY RUN] Would index {len(actions)} findings.")

    if len(state["processed_ids"]) > 50_000:
        state["processed_ids"] = state["processed_ids"][-50_000:]
    save_state(state)


def main():
    parser = argparse.ArgumentParser(description="Security Hub → Elasticsearch")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--once",    action="store_true")
    args = parser.parse_args()

    console.rule("[bold cyan]Security Hub → Elasticsearch[/bold cyan]")
    log.info(f"Region: {REGION} | Index: {ELASTIC_INDEX}")

    es = get_es()

    if args.once:
        run_poll(es, dry_run=args.dry_run)
        return

    run_poll(es, dry_run=args.dry_run)
    while True:
        time.sleep(POLL_INTERVAL)
        run_poll(es, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
