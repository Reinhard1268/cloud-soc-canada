#!/usr/bin/env python3
"""
azure-logs-to-elastic.py
Polls Azure Log Analytics workspace for security logs,
normalises to ECS format, and bulk-indexes into Elasticsearch.
"""

import os
import json
import time
import hashlib
import logging
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
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
log = logging.getLogger("azure-logs-to-elastic")

TENANT_ID     = os.getenv("AZURE_TENANT_ID", "")
CLIENT_ID     = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
WORKSPACE_ID  = os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "")
ELASTIC_URL   = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER  = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS  = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_INDEX = os.getenv("ELASTIC_SENTINEL_INDEX", "azure-sentinel-alerts")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_MINUTES", 5)) * 60
STATE_FILE    = Path("logs/azure_state.json")

# Tables to poll and their ECS dataset mapping
TABLES = {
    "SigninLogs":   "azure.signinlogs",
    "AuditLogs":    "azure.auditlogs",
    "AzureActivity": "azure.activitylogs",
    "SecurityAlert": "azure.securityalert",
}


def load_state() -> dict:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {t: {"last_ts": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}
            for t in TABLES}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_azure_client():
    cred   = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    return LogsQueryClient(cred)


def get_es() -> Elasticsearch:
    return Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USER, ELASTIC_PASS),
        verify_certs=False,
        ssl_show_warn=False,
    )


def row_to_dict(row, columns: list) -> dict:
    return {col: getattr(row, col, None) for col in columns}


def normalise_signinlog(row: dict) -> dict:
    ts = str(row.get("TimeGenerated", datetime.now(timezone.utc).isoformat()))
    upn = row.get("UserPrincipalName", "")
    ip  = row.get("IPAddress", "")
    result = str(row.get("ResultType", ""))
    outcome = "success" if result == "0" else "failure"

    doc_raw = f"{ts}:{upn}:{ip}:{result}"
    doc_id  = hashlib.sha256(doc_raw.encode()).hexdigest()

    return {
        "@timestamp": ts,
        "_doc_id":    doc_id,
        "event": {
            "kind":     "event",
            "category": ["authentication"],
            "type":     ["start"],
            "outcome":  outcome,
            "dataset":  "azure.signinlogs",
            "module":   "azure",
        },
        "cloud": {"provider": "azure", "region": "canadacentral"},
        "user": {"name": upn, "id": row.get("UserId", "")},
        "source": {"ip": ip, "address": ip},
        "user_agent": {"original": row.get("UserAgent", "")},
        "azure": {
            "signinlogs": {
                "result_type":   result,
                "result_desc":   row.get("ResultDescription", ""),
                "app_display":   row.get("AppDisplayName", ""),
                "client_app":    row.get("ClientAppUsed", ""),
                "conditional_access_status": row.get("ConditionalAccessStatus", ""),
                "location":      row.get("LocationDetails", {}),
                "device":        row.get("DeviceDetail", {}),
            }
        },
        "tags": ["azure", "signinlogs", outcome],
    }


def normalise_auditlog(row: dict) -> dict:
    ts  = str(row.get("TimeGenerated", datetime.now(timezone.utc).isoformat()))
    op  = row.get("OperationName", "")
    res = row.get("Result", "")

    doc_id = hashlib.sha256(f"{ts}:{op}:{res}".encode()).hexdigest()

    return {
        "@timestamp": ts,
        "_doc_id":    doc_id,
        "event": {
            "kind":     "event",
            "category": ["iam"],
            "type":     ["change"],
            "action":   op,
            "outcome":  "success" if res == "success" else "failure",
            "dataset":  "azure.auditlogs",
            "module":   "azure",
        },
        "cloud": {"provider": "azure", "region": "canadacentral"},
        "azure": {
            "auditlogs": {
                "operation_name":   op,
                "result":           res,
                "category":         row.get("Category", ""),
                "initiated_by":     row.get("InitiatedBy", {}),
                "target_resources": row.get("TargetResources", []),
            }
        },
        "tags": ["azure", "auditlogs"],
    }


def normalise_activity(row: dict) -> dict:
    ts     = str(row.get("TimeGenerated", datetime.now(timezone.utc).isoformat()))
    caller = row.get("Caller", "")
    op     = row.get("OperationNameValue", "")
    status = row.get("ActivityStatusValue", "")

    doc_id = hashlib.sha256(f"{ts}:{caller}:{op}".encode()).hexdigest()

    return {
        "@timestamp": ts,
        "_doc_id":    doc_id,
        "event": {
            "kind":    "event",
            "category": ["cloud"],
            "action":  op,
            "outcome": "success" if status.lower() == "success" else "failure",
            "dataset": "azure.activitylogs",
            "module":  "azure",
        },
        "cloud":  {"provider": "azure", "region": "canadacentral"},
        "user":   {"name": caller},
        "azure": {
            "activitylogs": {
                "operation_name":   op,
                "activity_status":  status,
                "resource_group":   row.get("ResourceGroup", ""),
                "subscription_id":  row.get("SubscriptionId", ""),
                "level":            row.get("Level", ""),
            }
        },
        "tags": ["azure", "activitylogs"],
    }


def normalise_securityalert(row: dict) -> dict:
    ts   = str(row.get("TimeGenerated", datetime.now(timezone.utc).isoformat()))
    name = row.get("AlertName", "")
    sev  = row.get("AlertSeverity", "Medium")

    doc_id = hashlib.sha256(f"{ts}:{name}:{sev}".encode()).hexdigest()

    return {
        "@timestamp": ts,
        "_doc_id":    doc_id,
        "event": {
            "kind":     "alert",
            "category": ["threat"],
            "action":   name,
            "outcome":  "success",
            "dataset":  "azure.securityalert",
            "module":   "azure",
        },
        "cloud":  {"provider": "azure", "region": "canadacentral"},
        "azure": {
            "securityalert": {
                "alert_name":        name,
                "alert_severity":    sev,
                "description":       row.get("Description", ""),
                "provider_name":     row.get("ProviderName", ""),
                "compromised_entity": row.get("CompromisedEntity", ""),
                "tactics":           row.get("Tactics", ""),
                "entities":          row.get("Entities", []),
            }
        },
        "tags": ["azure", "security-alert", sev.lower()],
    }


NORMALISERS = {
    "SigninLogs":    normalise_signinlog,
    "AuditLogs":     normalise_auditlog,
    "AzureActivity": normalise_activity,
    "SecurityAlert": normalise_securityalert,
}


def poll_table(client, table: str, last_ts: str) -> tuple:
    query = (
        f"{table}\n"
        f"| where TimeGenerated > datetime('{last_ts}')\n"
        f"| order by TimeGenerated asc\n"
        f"| limit 5000"
    )
    try:
        result = client.query_workspace(
            workspace_id=WORKSPACE_ID,
            query=query,
            timespan=timedelta(hours=24),
        )
        if result.status != LogsQueryStatus.SUCCESS:
            log.warning(f"{table}: query returned status {result.status}")
            return [], last_ts

        if not result.tables:
            return [], last_ts

        tbl     = result.tables[0]
        columns = [col.name for col in tbl.columns]
        rows    = [row_to_dict(r, columns) for r in tbl.rows]

        if rows:
            last_ts = str(rows[-1].get("TimeGenerated", last_ts))

        return rows, last_ts
    except Exception as e:
        log.error(f"Error querying {table}: {e}")
        return [], last_ts


def run_poll(es: Elasticsearch, dry_run: bool = False):
    log.info("─" * 60)
    log.info(f"[Poll] {datetime.now(timezone.utc).isoformat()}")

    state  = load_state()
    client = get_azure_client()

    total_indexed = 0
    for table, dataset in TABLES.items():
        last_ts = state.get(table, {}).get("last_ts", (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
        rows, new_ts = poll_table(client, table, last_ts)

        if not rows:
            log.info(f"{table}: no new rows")
            continue

        normaliser = NORMALISERS.get(table)
        ecs_docs   = [normaliser(r) for r in rows]
        actions    = []
        for doc in ecs_docs:
            doc_id = doc.pop("_doc_id", None)
            actions.append({"_index": ELASTIC_INDEX, "_id": doc_id, "_source": doc})

        if not dry_run:
            ok, errors = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
            log.info(f"{table}: indexed {ok} | errors {len(errors) if isinstance(errors, list) else errors}")
            total_indexed += ok
        else:
            log.info(f"[DRY RUN] {table}: would index {len(actions)} docs")

        state[table] = {"last_ts": new_ts}

    save_state(state)
    log.info(f"Total indexed this cycle: {total_indexed}")


def main():
    parser = argparse.ArgumentParser(description="Azure Log Analytics → Elasticsearch")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--once",    action="store_true")
    args = parser.parse_args()

    console.rule("[bold cyan]Azure Log Analytics → Elasticsearch[/bold cyan]")
    log.info(f"Workspace : {WORKSPACE_ID}")
    log.info(f"Tables    : {list(TABLES.keys())}")

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
