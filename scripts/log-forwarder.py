#!/usr/bin/env python3
"""
log-forwarder.py
Unified log forwarder for AWS (CloudTrail + GuardDuty) and Azure (Log Analytics).
Normalises all logs to ECS schema and bulk-indexes into Elasticsearch.
"""

import os
import io
import gzip
import json
import time
import hashlib
import logging
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

import boto3
import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn

load_dotenv()
console = Console()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger("log-forwarder")

# ── Config ─────────────────────────────────────────────────────
AWS_REGION          = os.getenv("AWS_DEFAULT_REGION", "ca-central-1")
CLOUDTRAIL_BUCKET   = os.getenv("AWS_CLOUDTRAIL_BUCKET", "")
GUARDDUTY_DETECTOR  = os.getenv("AWS_GUARDDUTY_DETECTOR_ID", "")
AZURE_TENANT_ID     = os.getenv("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID     = os.getenv("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
AZURE_WORKSPACE_ID  = os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "")
ELASTIC_URL         = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER        = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS        = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_INDEX       = os.getenv("ELASTIC_CLOUD_INDEX", "cloud-soc-logs")
POLL_INTERVAL       = int(os.getenv("POLL_INTERVAL_MINUTES", 5)) * 60
STATE_DIR           = Path("logs")
STATS_LOG           = Path("logs/forwarder.log")

# ── Helpers ─────────────────────────────────────────────────────
def doc_hash(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()


def get_es() -> Elasticsearch:
    return Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USER, ELASTIC_PASS),
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=30,
    )


def load_state(name: str) -> dict:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / f"{name}_state.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def save_state(name: str, state: dict):
    path = STATE_DIR / f"{name}_state.json"
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def write_stats(source: str, indexed: int, errors: int, duration: float):
    STATS_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source":    source,
        "indexed":   indexed,
        "errors":    errors,
        "duration_s": round(duration, 2),
    }
    with open(STATS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def exponential_backoff(attempt: int, base: float = 1.0, cap: float = 60.0):
    delay = min(base * (2 ** attempt), cap)
    time.sleep(delay)


# ── ECS Normalisation ───────────────────────────────────────────
def normalise_cloudtrail(record: dict) -> dict:
    ts       = record.get("eventTime", datetime.now(timezone.utc).isoformat())
    action   = record.get("eventName", "")
    src_ip   = record.get("sourceIPAddress", "")
    region   = record.get("awsRegion", AWS_REGION)
    err_code = record.get("errorCode", "")
    identity = record.get("userIdentity", {})
    username = (identity.get("userName")
                or identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName", "unknown"))
    doc_id = doc_hash(ts, action, identity.get("arn", ""), src_ip)
    return {
        "@timestamp": ts, "_doc_id": doc_id,
        "event": {"kind": "event", "action": action,
                  "outcome": "failure" if err_code else "success",
                  "dataset": "aws.cloudtrail", "module": "aws"},
        "cloud":  {"provider": "aws", "region": region,
                   "account": {"id": identity.get("accountId", "")}},
        "user":   {"name": username, "id": identity.get("arn", "")},
        "source": {"ip": src_ip, "address": src_ip},
        "aws":    {"cloudtrail": {"event_type": record.get("eventType", ""),
                                   "error_code": err_code,
                                   "read_only":  record.get("readOnly", False)}},
        "tags":   ["cloudtrail", "aws", "ca-central-1"],
    }


def normalise_guardduty(finding: dict) -> dict:
    ts    = finding.get("UpdatedAt", datetime.now(timezone.utc).isoformat())
    ftype = finding.get("Type", "")
    sev   = finding.get("Severity", 0)
    sev_label = ("critical" if sev >= 7 else "high" if sev >= 5 else "medium" if sev >= 3 else "low")
    doc_id = doc_hash(finding.get("Id", ts))
    return {
        "@timestamp": ts, "_doc_id": doc_id,
        "event": {"kind": "alert", "action": ftype,
                  "dataset": "aws.guardduty", "module": "aws",
                  "severity": int(sev)},
        "cloud": {"provider": "aws", "region": finding.get("Region", AWS_REGION),
                  "account": {"id": finding.get("AccountId", "")}},
        "aws":   {"guardduty": {"finding_type": ftype, "severity": sev,
                                 "severity_label": sev_label,
                                 "title": finding.get("Title", ""),
                                 "finding_id": finding.get("Id", "")}},
        "tags":  ["guardduty", "aws", "ca-central-1", sev_label],
    }


def normalise_azure_row(row: dict, table: str) -> dict:
    ts     = str(row.get("TimeGenerated", datetime.now(timezone.utc).isoformat()))
    action = str(row.get("OperationName", row.get("OperationNameValue", "")))
    user   = str(row.get("UserPrincipalName", row.get("Caller", "")))
    doc_id = doc_hash(ts, action, user, table)
    outcome = ("success" if str(row.get("ResultType", row.get("ActivityStatusValue", "success"))) in ("0", "success", "Success") else "failure")
    return {
        "@timestamp": ts, "_doc_id": doc_id,
        "event": {"kind": "event", "action": action, "outcome": outcome,
                  "dataset": f"azure.{table.lower()}", "module": "azure"},
        "cloud": {"provider": "azure", "region": "canadacentral"},
        "user":  {"name": user},
        "azure": {table.lower(): {k: str(v) for k, v in row.items() if v is not None}},
        "tags":  ["azure", table.lower(), "canadacentral"],
    }


# ── AWS Sources ─────────────────────────────────────────────────
def forward_cloudtrail(es: Elasticsearch, dry_run: bool, backfill_hours: int) -> tuple:
    if not CLOUDTRAIL_BUCKET:
        log.warning("AWS_CLOUDTRAIL_BUCKET not set — skipping CloudTrail")
        return 0, 0

    state  = load_state("cloudtrail")
    s3     = boto3.client("s3", region_name=AWS_REGION)
    processed = set(state.get("processed_keys", []))
    new_keys  = []

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=CLOUDTRAIL_BUCKET, Prefix="cloudtrail/"):
        for obj in page.get("Contents", []):
            k = obj["Key"]
            if k.endswith(".json.gz") and k not in processed:
                new_keys.append(k)

    log.info(f"[CloudTrail] {len(new_keys)} new log file(s)")
    total_ok = total_err = 0
    actions  = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                  TaskProgressColumn(), console=console) as prog:
        task = prog.add_task("CloudTrail files…", total=len(new_keys))
        for key in new_keys:
            for attempt in range(3):
                try:
                    resp = s3.get_object(Bucket=CLOUDTRAIL_BUCKET, Key=key)
                    with gzip.GzipFile(fileobj=io.BytesIO(resp["Body"].read())) as gz:
                        records = json.loads(gz.read()).get("Records", [])
                    for r in records:
                        doc = normalise_cloudtrail(r)
                        doc_id = doc.pop("_doc_id", None)
                        actions.append({"_index": ELASTIC_INDEX, "_id": doc_id, "_source": doc})
                    processed.add(key)
                    break
                except Exception as e:
                    log.warning(f"Retry {attempt+1} for {key}: {e}")
                    exponential_backoff(attempt)
            prog.advance(task)

    if not dry_run and actions:
        ok, errs = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
        total_ok  += ok
        total_err += len(errs) if isinstance(errs, list) else errs

    state["processed_keys"] = list(processed)[-10_000:]
    save_state("cloudtrail", state)
    return total_ok, total_err


def forward_guardduty(es: Elasticsearch, dry_run: bool) -> tuple:
    if not GUARDDUTY_DETECTOR:
        log.warning("AWS_GUARDDUTY_DETECTOR_ID not set — skipping GuardDuty")
        return 0, 0

    state     = load_state("guardduty")
    processed = set(state.get("processed_ids", []))
    gd        = boto3.client("guardduty", region_name=AWS_REGION)
    fids      = []

    paginator = gd.get_paginator("list_findings")
    for page in paginator.paginate(DetectorId=GUARDDUTY_DETECTOR,
                                    FindingCriteria={"Criterion": {"severity": {"Gte": 4}}}):
        for fid in page.get("FindingIds", []):
            if fid not in processed:
                fids.append(fid)

    log.info(f"[GuardDuty] {len(fids)} new finding(s)")
    total_ok = total_err = 0
    actions  = []

    for i in range(0, len(fids), 50):
        batch    = fids[i:i+50]
        findings = gd.get_findings(DetectorId=GUARDDUTY_DETECTOR, FindingIds=batch).get("Findings", [])
        for f in findings:
            doc = normalise_guardduty(f)
            doc_id = doc.pop("_doc_id", None)
            actions.append({"_index": ELASTIC_INDEX, "_id": doc_id, "_source": doc})
            processed.add(f.get("Id", ""))

    if not dry_run and actions:
        ok, errs = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
        total_ok  = ok
        total_err = len(errs) if isinstance(errs, list) else errs

    state["processed_ids"] = list(processed)[-50_000:]
    save_state("guardduty", state)
    return total_ok, total_err


# ── Azure Source ────────────────────────────────────────────────
def forward_azure(es: Elasticsearch, dry_run: bool, services: list) -> tuple:
    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_WORKSPACE_ID]):
        log.warning("Azure credentials incomplete — skipping Azure")
        return 0, 0

    try:
        from azure.identity import ClientSecretCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus
    except ImportError:
        log.error("azure-identity / azure-monitor-query not installed")
        return 0, 0

    cred   = ClientSecretCredential(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
    client = LogsQueryClient(cred)
    state  = load_state("azure")
    tables = {
        "SigninLogs":   "azure.signinlogs",
        "AuditLogs":    "azure.auditlogs",
        "AzureActivity": "azure.activitylogs",
    }
    if "sentinel" in services or "all" in services:
        tables["SecurityAlert"] = "azure.securityalert"

    total_ok = total_err = 0
    for table in tables:
        last_ts = state.get(table, {}).get("last_ts",
                    (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
        query  = f"{table}\n| where TimeGenerated > datetime('{last_ts}')\n| order by TimeGenerated asc\n| limit 5000"
        actions = []
        try:
            result = client.query_workspace(AZURE_WORKSPACE_ID, query, timespan=timedelta(hours=24))
            if result.status == LogsQueryStatus.SUCCESS and result.tables:
                tbl     = result.tables[0]
                cols    = [c.name for c in tbl.columns]
                rows    = [{col: getattr(r, col, None) for col in cols} for r in tbl.rows]
                for row in rows:
                    doc = normalise_azure_row(row, table)
                    doc_id = doc.pop("_doc_id", None)
                    actions.append({"_index": ELASTIC_INDEX, "_id": doc_id, "_source": doc})
                if rows:
                    state[table] = {"last_ts": str(rows[-1].get("TimeGenerated", last_ts))}
                log.info(f"[Azure/{table}] {len(rows)} row(s)")
        except Exception as e:
            log.error(f"Azure query error for {table}: {e}")

        if not dry_run and actions:
            ok, errs = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
            total_ok  += ok
            total_err += len(errs) if isinstance(errs, list) else errs
        elif dry_run:
            log.info(f"[DRY RUN] Azure/{table}: would index {len(actions)}")

    save_state("azure", state)
    return total_ok, total_err


# ── Main ─────────────────────────────────────────────────────────
def run(args):
    es     = get_es()
    source = args.source
    svc    = args.service.lower()
    start  = time.time()
    total_ok = total_err = 0

    console.rule(f"[bold cyan]Log Forwarder — source={source} service={svc}[/bold cyan]")

    if source in ("aws", "both"):
        if svc in ("cloudtrail", "all"):
            ok, err = forward_cloudtrail(es, args.dry_run, args.backfill_hours)
            total_ok += ok; total_err += err
            write_stats("cloudtrail", ok, err, time.time() - start)
        if svc in ("guardduty", "all"):
            ok, err = forward_guardduty(es, args.dry_run)
            total_ok += ok; total_err += err
            write_stats("guardduty", ok, err, time.time() - start)

    if source in ("azure", "both"):
        ok, err = forward_azure(es, args.dry_run, [svc])
        total_ok += ok; total_err += err
        write_stats("azure", ok, err, time.time() - start)

    duration = round(time.time() - start, 2)
    log.info(f"Done. Indexed: {total_ok} | Errors: {total_err} | Duration: {duration}s")


def main():
    parser = argparse.ArgumentParser(description="Unified Cloud Log Forwarder → Elasticsearch")
    parser.add_argument("--source",        choices=["aws", "azure", "both"], default="both")
    parser.add_argument("--service",       default="all",
                        help="cloudtrail | guardduty | sentinel | all")
    parser.add_argument("--dry-run",       action="store_true")
    parser.add_argument("--once",          action="store_true")
    parser.add_argument("--backfill-hours", type=int, default=24, dest="backfill_hours")
    parser.add_argument("--verbose",       action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.once:
        run(args)
        return

    run(args)
    while True:
        time.sleep(POLL_INTERVAL)
        run(args)


if __name__ == "__main__":
    main()
