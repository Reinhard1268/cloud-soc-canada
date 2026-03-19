#!/usr/bin/env python3
"""
cloudtrail-to-elastic.py
Polls S3 for new CloudTrail log files, normalises to ECS format,
and bulk-indexes into Elasticsearch. Runs every 5 minutes.
"""

import os
import io
import gzip
import json
import time
import hashlib
import logging
import argparse
import schedule
from datetime import datetime, timezone
from pathlib import Path

import boto3
import botocore
from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# ── Bootstrap ─────────────────────────────────────────────────
load_dotenv()
console = Console()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger("cloudtrail-to-elastic")

# ── Config ────────────────────────────────────────────────────
BUCKET_NAME        = os.getenv("AWS_CLOUDTRAIL_BUCKET")
REGION             = os.getenv("AWS_DEFAULT_REGION", "ca-central-1")
ELASTIC_URL        = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER       = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD   = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_INDEX      = os.getenv("ELASTIC_CLOUDTRAIL_INDEX", "aws-cloudtrail-events")
POLL_MINUTES       = int(os.getenv("POLL_INTERVAL_MINUTES", 5))
STATE_FILE         = Path("logs/cloudtrail_state.json")


# ── State Management (deduplication) ─────────────────────────
def load_state() -> dict:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"processed_keys": []}


def save_state(state: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ── AWS Clients ───────────────────────────────────────────────
def get_s3_client():
    return boto3.client("s3", region_name=REGION)


# ── Elasticsearch Client ──────────────────────────────────────
def get_es_client() -> Elasticsearch:
    return Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=30,
    )


# ── ECS Normalisation ─────────────────────────────────────────
def normalise_to_ecs(raw_event: dict) -> dict:
    """Convert a CloudTrail event record to ECS-compatible format."""
    event_time = raw_event.get("eventTime", "")
    source_ip  = raw_event.get("sourceIPAddress", "")
    user_agent = raw_event.get("userAgent", "")
    event_name = raw_event.get("eventName", "")
    event_src  = raw_event.get("eventSource", "")
    aws_region = raw_event.get("awsRegion", REGION)
    error_code = raw_event.get("errorCode", "")
    error_msg  = raw_event.get("errorMessage", "")

    user_identity = raw_event.get("userIdentity", {})
    user_type     = user_identity.get("type", "")
    user_arn      = user_identity.get("arn", "")
    account_id    = user_identity.get("accountId", "")
    username      = (
        user_identity.get("userName")
        or user_identity.get("sessionContext", {})
                       .get("sessionIssuer", {})
                       .get("userName", "unknown")
    )

    # Determine outcome
    outcome = "failure" if error_code else "success"

    # Generate a stable document ID
    doc_id_raw = f"{event_time}:{event_name}:{user_arn}:{source_ip}"
    doc_id = hashlib.sha256(doc_id_raw.encode()).hexdigest()

    ecs_doc = {
        "@timestamp": event_time,
        "event": {
            "id":       raw_event.get("eventID", ""),
            "kind":     "event",
            "category": ["authentication"] if "Login" in event_name or "Signin" in event_name else ["cloud"],
            "type":     ["info"],
            "action":   event_name,
            "outcome":  outcome,
            "provider": event_src,
            "dataset":  "aws.cloudtrail",
            "module":   "aws",
        },
        "cloud": {
            "provider":    "aws",
            "region":      aws_region,
            "account":     {"id": account_id},
            "service":     {"name": event_src.replace(".amazonaws.com", "")},
        },
        "user": {
            "name": username,
            "id":   user_arn,
        },
        "source": {
            "ip":         source_ip,
            "address":    source_ip,
        },
        "user_agent": {
            "original": user_agent,
        },
        "aws": {
            "cloudtrail": {
                "event_version":   raw_event.get("eventVersion", ""),
                "event_type":      raw_event.get("eventType", ""),
                "user_identity":   user_identity,
                "request_params":  raw_event.get("requestParameters"),
                "response_elems":  raw_event.get("responseElements"),
                "error_code":      error_code,
                "error_message":   error_msg,
                "read_only":       raw_event.get("readOnly", False),
                "resources":       raw_event.get("resources", []),
                "recipient_acct":  raw_event.get("recipientAccountId", account_id),
            }
        },
        "error": {
            "code":    error_code,
            "message": error_msg,
        } if error_code else {},
        "tags": ["cloudtrail", "aws", "ca-central-1"],
        "_doc_id": doc_id,
    }
    return ecs_doc


# ── Fetch New Log Files from S3 ───────────────────────────────
def list_new_log_files(s3, state: dict) -> list:
    processed = set(state.get("processed_keys", []))
    new_keys = []
    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(
        Bucket=BUCKET_NAME,
        Prefix="cloudtrail/",
    )
    for page in pages:
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json.gz") and key not in processed:
                new_keys.append(key)
    log.info(f"Found {len(new_keys)} new CloudTrail log file(s) to process.")
    return new_keys


# ── Download + Decompress ─────────────────────────────────────
def download_and_parse(s3, key: str) -> list:
    response = s3.get_object(Bucket=BUCKET_NAME, Key=key)
    compressed = response["Body"].read()
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz:
        raw = json.loads(gz.read().decode("utf-8"))
    return raw.get("Records", [])


# ── Bulk Index to Elasticsearch ───────────────────────────────
def bulk_index(es: Elasticsearch, docs: list) -> tuple:
    actions = []
    for doc in docs:
        doc_id = doc.pop("_doc_id", None)
        action = {
            "_index": ELASTIC_INDEX,
            "_source": doc,
        }
        if doc_id:
            action["_id"] = doc_id
        actions.append(action)

    if not actions:
        return 0, 0

    success_count, errors = helpers.bulk(
        es, actions, raise_on_error=False, stats_only=False
    )
    return success_count, len(errors) if isinstance(errors, list) else errors


# ── Main Poll Cycle ───────────────────────────────────────────
def run_poll(dry_run: bool = False) -> None:
    log.info("─" * 60)
    log.info(f"[Poll cycle] {datetime.now(timezone.utc).isoformat()}")

    state = load_state()
    s3    = get_s3_client()
    es    = get_es_client()

    try:
        new_keys = list_new_log_files(s3, state)
    except botocore.exceptions.ClientError as e:
        log.error(f"S3 list error: {e}")
        return

    if not new_keys:
        log.info("No new CloudTrail logs. Nothing to do.")
        return

    total_indexed = 0
    total_errors  = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing log files…", total=len(new_keys))

        for key in new_keys:
            try:
                records = download_and_parse(s3, key)
                ecs_docs = [normalise_to_ecs(r) for r in records]

                if dry_run:
                    log.info(f"[DRY RUN] Would index {len(ecs_docs)} events from {key}")
                else:
                    ok, err = bulk_index(es, ecs_docs)
                    total_indexed += ok
                    total_errors  += err
                    log.info(f"Indexed {ok} events from {key} ({err} errors)")

                state["processed_keys"].append(key)
                # Keep state file trim — only last 10,000 keys
                if len(state["processed_keys"]) > 10_000:
                    state["processed_keys"] = state["processed_keys"][-10_000:]

            except Exception as exc:
                log.error(f"Failed to process {key}: {exc}")

            progress.advance(task)

    save_state(state)
    log.info(f"Poll complete. Total indexed: {total_indexed} | Errors: {total_errors}")


# ── Entry Point ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CloudTrail → Elasticsearch forwarder")
    parser.add_argument("--dry-run",   action="store_true", help="Parse but do not index")
    parser.add_argument("--once",      action="store_true", help="Run once and exit")
    parser.add_argument("--interval",  type=int, default=POLL_MINUTES, help="Poll interval in minutes")
    args = parser.parse_args()

    console.rule("[bold cyan]CloudTrail → Elasticsearch[/bold cyan]")
    log.info(f"Bucket : {BUCKET_NAME}")
    log.info(f"Index  : {ELASTIC_INDEX}")
    log.info(f"Region : {REGION}")
    log.info(f"Interval: every {args.interval} minute(s)")

    if args.once:
        run_poll(dry_run=args.dry_run)
        return

    schedule.every(args.interval).minutes.do(run_poll, dry_run=args.dry_run)
    run_poll(dry_run=args.dry_run)  # immediate first run

    while True:
        schedule.run_pending()
        time.sleep(30)


if __name__ == "__main__":
    main()
