#!/usr/bin/env python3
"""
guardduty-findings-to-elastic.py
Polls GuardDuty findings, enriches with GeoIP/ASN/account context,
normalises to ECS, indexes to Elasticsearch, and creates TheHive
alerts for HIGH/CRITICAL findings.
"""

import os
import json
import time
import hashlib
import logging
import argparse
import requests
from datetime import datetime, timezone
from pathlib import Path

import boto3
from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers
from rich.console import Console
from rich.logging import RichHandler

load_dotenv()
console = Console()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger("guardduty-to-elastic")

# ── Config ─────────────────────────────────────────────────────
REGION         = os.getenv("AWS_DEFAULT_REGION", "ca-central-1")
DETECTOR_ID    = os.getenv("AWS_GUARDDUTY_DETECTOR_ID", "")
ELASTIC_URL    = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER   = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS   = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_INDEX  = os.getenv("ELASTIC_GUARDDUTY_INDEX", "aws-guardduty-findings")
THEHIVE_URL    = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_KEY    = os.getenv("THEHIVE_API_KEY", "")
POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL_MINUTES", 5)) * 60
MIN_SEVERITY   = 4.0   # Medium and above
STATE_FILE     = Path("logs/guardduty_state.json")


# ── State ──────────────────────────────────────────────────────
def load_state() -> dict:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"processed_ids": []}


def save_state(state: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ── GeoIP Enrichment ──────────────────────────────────────────
def enrich_ip(ip: str) -> dict:
    if not ip or ip.startswith(("10.", "172.", "192.168.", "127.")):
        return {"ip": ip, "geo": {}, "asn": {}}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
            "regionName,city,lat,lon,isp,org,as",
            timeout=5
        )
        data = r.json()
        if data.get("status") == "success":
            return {
                "ip": ip,
                "geo": {
                    "country_name":    data.get("country"),
                    "country_iso_code": data.get("countryCode"),
                    "region_name":     data.get("regionName"),
                    "city_name":       data.get("city"),
                    "location": {
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                    }
                },
                "asn": {
                    "organization": data.get("org"),
                    "isp":          data.get("isp"),
                    "as_number":    data.get("as"),
                }
            }
    except Exception as e:
        log.debug(f"GeoIP lookup failed for {ip}: {e}")
    return {"ip": ip, "geo": {}, "asn": {}}


# ── ECS Normalisation ──────────────────────────────────────────
def normalise_finding(finding: dict) -> dict:
    severity_score = finding.get("Severity", 0)
    severity_label = (
        "critical" if severity_score >= 7.0 else
        "high"     if severity_score >= 5.0 else
        "medium"   if severity_score >= 3.0 else
        "low"
    )

    service     = finding.get("Service", {})
    action      = service.get("Action", {})
    action_type = action.get("ActionType", "UNKNOWN")
    resource    = finding.get("Resource", {})
    account_id  = finding.get("AccountId", "")
    region      = finding.get("Region", REGION)

    # Extract remote IP if present
    remote_ip = ""
    if action_type == "NETWORK_CONNECTION":
        conn = action.get("NetworkConnectionAction", {})
        remote_ip = conn.get("RemoteIpDetails", {}).get("IpAddressV4", "")
    elif action_type == "AWS_API_CALL":
        remote_ip = action.get("AwsApiCallAction", {}) \
                          .get("RemoteIpDetails", {}) \
                          .get("IpAddressV4", "")

    geo_data = enrich_ip(remote_ip) if remote_ip else {}

    doc_id = hashlib.sha256(finding.get("Id", "").encode()).hexdigest()

    ecs = {
        "@timestamp": finding.get("UpdatedAt", datetime.now(timezone.utc).isoformat()),
        "event": {
            "id":       finding.get("Id", ""),
            "kind":     "alert",
            "category": ["threat"],
            "type":     ["indicator"],
            "action":   finding.get("Type", ""),
            "outcome":  "success",
            "severity": int(severity_score),
            "dataset":  "aws.guardduty",
            "module":   "aws",
        },
        "cloud": {
            "provider":  "aws",
            "region":    region,
            "account":   {"id": account_id},
        },
        "threat": {
            "indicator": {
                "description": finding.get("Description", ""),
                "type":        action_type,
            }
        },
        "source": {
            "ip":      remote_ip,
            "address": remote_ip,
            "geo":     geo_data.get("geo", {}),
            "as":      geo_data.get("asn", {}),
        },
        "aws": {
            "guardduty": {
                "finding_id":    finding.get("Id"),
                "finding_type":  finding.get("Type"),
                "severity":      severity_score,
                "severity_label": severity_label,
                "title":         finding.get("Title"),
                "description":   finding.get("Description"),
                "account_id":    account_id,
                "region":        region,
                "resource":      resource,
                "service":       service,
                "created_at":    finding.get("CreatedAt"),
                "updated_at":    finding.get("UpdatedAt"),
                "count":         service.get("Count", 0),
                "archived":      service.get("Archived", False),
            }
        },
        "labels": {
            "severity_label": severity_label,
            "finding_type":   finding.get("Type", ""),
            "region":         region,
        },
        "tags": ["guardduty", "aws", "ca-central-1", severity_label],
        "_doc_id": doc_id,
        "_severity_label": severity_label,
        "_finding_title":  finding.get("Title", ""),
        "_finding_id":     finding.get("Id", ""),
    }
    return ecs


# ── TheHive Alert ──────────────────────────────────────────────
def create_thehive_alert(doc: dict) -> bool:
    if not THEHIVE_KEY:
        log.warning("THEHIVE_API_KEY not set — skipping alert creation.")
        return False

    severity_map = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    sev_label    = doc.get("_severity_label", "medium")
    gd           = doc.get("aws", {}).get("guardduty", {})

    payload = {
        "title":       f"[GuardDuty] {doc.get('_finding_title', 'Unknown Finding')}",
        "description": gd.get("description", ""),
        "type":        "aws-guardduty",
        "source":      "guardduty-findings-to-elastic",
        "sourceRef":   doc.get("_finding_id", ""),
        "severity":    severity_map.get(sev_label, 1),
        "tags":        ["guardduty", "aws", "ca-central-1", sev_label],
        "tlp":         2,
        "artifacts": [
            {
                "dataType": "ip",
                "data":     doc.get("source", {}).get("ip", ""),
                "message":  "Remote IP from GuardDuty finding",
            }
        ] if doc.get("source", {}).get("ip") else [],
    }

    try:
        r = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            json=payload,
            headers={
                "Authorization": f"Bearer {THEHIVE_KEY}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        if r.status_code in (200, 201):
            log.info(f"TheHive alert created for finding: {doc.get('_finding_id')}")
            return True
        else:
            log.warning(f"TheHive returned {r.status_code}: {r.text[:200]}")
    except Exception as e:
        log.error(f"TheHive alert creation failed: {e}")
    return False


# ── Fetch Findings from GuardDuty ──────────────────────────────
def fetch_findings(gd_client, state: dict) -> list:
    processed = set(state.get("processed_ids", []))
    finding_ids = []
    paginator = gd_client.get_paginator("list_findings")
    pages = paginator.paginate(
        DetectorId=DETECTOR_ID,
        FindingCriteria={
            "Criterion": {
                "severity": {"Gte": int(MIN_SEVERITY * 10) // 10}
            }
        },
        SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
    )
    for page in pages:
        for fid in page.get("FindingIds", []):
            if fid not in processed:
                finding_ids.append(fid)

    if not finding_ids:
        return []

    # GuardDuty returns max 50 findings per get_findings call
    all_findings = []
    for i in range(0, len(finding_ids), 50):
        batch = finding_ids[i:i+50]
        response = gd_client.get_findings(
            DetectorId=DETECTOR_ID,
            FindingIds=batch,
        )
        all_findings.extend(response.get("Findings", []))

    log.info(f"Fetched {len(all_findings)} new GuardDuty finding(s).")
    return all_findings


# ── Main Poll Cycle ────────────────────────────────────────────
def run_poll(es: Elasticsearch, dry_run: bool = False) -> None:
    log.info("─" * 60)
    log.info(f"[Poll] {datetime.now(timezone.utc).isoformat()}")

    if not DETECTOR_ID:
        log.error("AWS_GUARDDUTY_DETECTOR_ID not set in .env")
        return

    state     = load_state()
    gd_client = boto3.client("guardduty", region_name=REGION)

    findings = fetch_findings(gd_client, state)
    if not findings:
        log.info("No new findings.")
        return

    actions = []
    hive_count = 0

    for finding in findings:
        doc = normalise_finding(finding)
        finding_id    = doc.pop("_finding_id", None)
        severity_label = doc.pop("_severity_label", "low")
        doc.pop("_finding_title", None)
        doc_id        = doc.pop("_doc_id", None)

        if not dry_run:
            actions.append({
                "_index":  ELASTIC_INDEX,
                "_id":     doc_id,
                "_source": doc,
            })
            if severity_label in ("high", "critical"):
                # Re-attach for TheHive
                doc["_finding_id"]     = finding_id
                doc["_severity_label"] = severity_label
                doc["_finding_title"]  = finding.get("Title", "")
                create_thehive_alert(doc)
                hive_count += 1

        state["processed_ids"].append(finding_id)

    if not dry_run and actions:
        ok, errors = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
        log.info(f"Indexed {ok} findings | Errors: {len(errors) if isinstance(errors, list) else errors} | TheHive alerts: {hive_count}")
    elif dry_run:
        log.info(f"[DRY RUN] Would index {len(findings)} findings.")

    # Trim state
    if len(state["processed_ids"]) > 50_000:
        state["processed_ids"] = state["processed_ids"][-50_000:]
    save_state(state)


# ── Entry Point ────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="GuardDuty → Elasticsearch")
    parser.add_argument("--dry-run",  action="store_true")
    parser.add_argument("--once",     action="store_true")
    parser.add_argument("--interval", type=int, default=int(POLL_INTERVAL // 60))
    args = parser.parse_args()

    console.rule("[bold cyan]GuardDuty → Elasticsearch[/bold cyan]")
    log.info(f"Detector : {DETECTOR_ID}")
    log.info(f"Region   : {REGION}")
    log.info(f"Min Sev  : {MIN_SEVERITY}")

    es = Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USER, ELASTIC_PASS),
        verify_certs=False,
        ssl_show_warn=False,
    )

    if args.once:
        run_poll(es, dry_run=args.dry_run)
        return

    run_poll(es, dry_run=args.dry_run)
    interval_secs = args.interval * 60
    while True:
        time.sleep(interval_secs)
        run_poll(es, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
