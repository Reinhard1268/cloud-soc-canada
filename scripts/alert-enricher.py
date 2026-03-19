#!/usr/bin/env python3
"""
alert-enricher.py
Reads new cloud alerts from Elasticsearch, enriches each alert with
IP reputation, GeoIP/ASN, MITRE ATT&CK mappings, and risk scores,
then updates the document and optionally creates TheHive alerts.
"""

import os
import json
import time
import logging
import argparse
from datetime import datetime, timezone, timedelta

import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
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
log = logging.getLogger("alert-enricher")

ELASTIC_URL      = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER     = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS     = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_INDEX    = os.getenv("ELASTIC_CLOUD_INDEX", "cloud-soc-logs")
THEHIVE_URL      = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_KEY      = os.getenv("THEHIVE_API_KEY", "")
ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
RISK_THRESHOLD   = 70
POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL_MINUTES", 5)) * 60

# ── MITRE ATT&CK Mapping ──────────────────────────────────────
MITRE_MAPPING = {
    "AttachUserPolicy":           {"technique": "T1098", "tactic": "PrivilegeEscalation", "name": "Account Manipulation"},
    "AttachRolePolicy":           {"technique": "T1098", "tactic": "PrivilegeEscalation", "name": "Account Manipulation"},
    "CreateUser":                 {"technique": "T1136", "tactic": "Persistence",         "name": "Create Account"},
    "ConsoleLogin":               {"technique": "T1078", "tactic": "InitialAccess",        "name": "Valid Accounts"},
    "StopLogging":                {"technique": "T1562.008", "tactic": "DefenseEvasion",  "name": "Disable Cloud Logs"},
    "PutBucketAcl":               {"technique": "T1530", "tactic": "Exfiltration",        "name": "Data from Cloud Storage"},
    "GetSecretValue":             {"technique": "T1552.001", "tactic": "CredentialAccess","name": "Credentials In Files"},
    "Add member to role":         {"technique": "T1098", "tactic": "PrivilegeEscalation", "name": "Account Manipulation"},
    "CryptoCurrency":             {"technique": "T1496", "tactic": "Impact",              "name": "Resource Hijacking"},
    "UnauthorizedAccess":         {"technique": "T1078", "tactic": "InitialAccess",        "name": "Valid Accounts"},
    "Recon":                      {"technique": "T1595", "tactic": "Reconnaissance",      "name": "Active Scanning"},
    "Trojan":                     {"technique": "T1204", "tactic": "Execution",            "name": "User Execution"},
    "Backdoor":                   {"technique": "T1543", "tactic": "Persistence",         "name": "Create or Modify System Process"},
    "Behavior":                   {"technique": "T1071", "tactic": "CommandAndControl",   "name": "Application Layer Protocol"},
    "Exfiltration":               {"technique": "T1537", "tactic": "Exfiltration",        "name": "Transfer Data to Cloud Account"},
    "ImpossibleTravel":           {"technique": "T1078", "tactic": "InitialAccess",        "name": "Valid Accounts"},
    "BruteForce":                 {"technique": "T1110", "tactic": "CredentialAccess",    "name": "Brute Force"},
    "LateralMovement":            {"technique": "T1550", "tactic": "LateralMovement",     "name": "Use Alternate Auth Material"},
    "PrivilegeEscalation":        {"technique": "T1548", "tactic": "PrivilegeEscalation", "name": "Abuse Elevation Control"},
}

# ── Asset Value Map (account/subscription → business value) ──
ASSET_VALUE = {
    "production":  10,
    "prod":        10,
    "staging":     6,
    "dev":         3,
    "test":        2,
    "lab":         1,
}


def get_es() -> Elasticsearch:
    return Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USER, ELASTIC_PASS),
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=30,
    )


# ── IP Reputation (AbuseIPDB) ─────────────────────────────────
def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY or not ip:
        return {}
    if ip.startswith(("10.", "172.", "192.168.", "127.")):
        return {"score": 0, "is_public": False}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        data = r.json().get("data", {})
        return {
            "score":              data.get("abuseConfidenceScore", 0),
            "total_reports":      data.get("totalReports", 0),
            "country_code":       data.get("countryCode", ""),
            "usage_type":         data.get("usageType", ""),
            "isp":                data.get("isp", ""),
            "is_tor":             data.get("isTor", False),
            "last_reported":      data.get("lastReportedAt", ""),
            "is_public":          data.get("isPublic", True),
        }
    except Exception as e:
        log.debug(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {}


# ── GeoIP + ASN (ip-api.com) ──────────────────────────────────
def geoip_lookup(ip: str) -> dict:
    if not ip or ip.startswith(("10.", "172.", "192.168.", "127.")):
        return {}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting",
            timeout=5,
        )
        data = r.json()
        if data.get("status") == "success":
            return {
                "country":      data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "region":       data.get("regionName", ""),
                "city":         data.get("city", ""),
                "lat":          data.get("lat"),
                "lon":          data.get("lon"),
                "isp":          data.get("isp", ""),
                "org":          data.get("org", ""),
                "as":           data.get("as", ""),
                "is_proxy":     data.get("proxy", False),
                "is_hosting":   data.get("hosting", False),
            }
    except Exception as e:
        log.debug(f"GeoIP lookup failed for {ip}: {e}")
    return {}


# ── AWS Account Name from ID ──────────────────────────────────
ACCOUNT_NAMES = {
    "123456789012": "soc-lab-primary",
}

def get_aws_account_name(account_id: str) -> str:
    return ACCOUNT_NAMES.get(account_id, f"aws-account-{account_id}")


# ── MITRE ATT&CK Mapping ──────────────────────────────────────
def map_mitre(action: str, finding_type: str) -> dict:
    for key, val in MITRE_MAPPING.items():
        if key.lower() in action.lower() or key.lower() in finding_type.lower():
            return val
    return {}


# ── Risk Score Calculation ────────────────────────────────────
def calculate_risk_score(severity: int, abuse_score: int,
                          is_tor: bool, is_proxy: bool,
                          asset_env: str) -> int:
    base        = min(severity * 10, 100)
    ip_risk     = min(abuse_score // 10, 20)
    tor_bonus   = 15 if is_tor else 0
    proxy_bonus = 10 if is_proxy else 0
    asset_mult  = ASSET_VALUE.get(asset_env.lower(), 5)
    score       = int(min((base + ip_risk + tor_bonus + proxy_bonus) * (asset_mult / 10), 100))
    return score


# ── TheHive Alert ─────────────────────────────────────────────
def create_thehive_alert(doc: dict, risk_score: int) -> bool:
    if not THEHIVE_KEY:
        return False
    sev_map = {range(80, 101): 3, range(50, 80): 2, range(0, 50): 1}
    sev = next((v for k, v in sev_map.items() if risk_score in k), 1)
    action     = doc.get("event", {}).get("action", "Unknown Action")
    cloud_prov = doc.get("cloud", {}).get("provider", "cloud")
    src_ip     = doc.get("source", {}).get("ip", "")
    enrichment = doc.get("enrichment", {})
    payload = {
        "title":     f"[Cloud Alert] {action} — Risk Score: {risk_score}",
        "type":      "cloud-soc-alert",
        "source":    "alert-enricher",
        "sourceRef": doc.get("event", {}).get("id", str(risk_score)),
        "severity":  sev,
        "tags":      ["cloud", cloud_prov, f"risk-{risk_score}"],
        "tlp":       2,
        "description": (
            f"**Risk Score:** {risk_score}/100\n"
            f"**Source IP:** {src_ip}\n"
            f"**AbuseIPDB Score:** {enrichment.get('ip_reputation', {}).get('score', 'N/A')}\n"
            f"**GeoIP:** {enrichment.get('geoip', {}).get('country', 'Unknown')}\n"
            f"**MITRE:** {enrichment.get('mitre', {}).get('technique', 'N/A')} - "
            f"{enrichment.get('mitre', {}).get('name', 'N/A')}\n"
        ),
        "artifacts": [
            {"dataType": "ip", "data": src_ip, "message": "Source IP"}
        ] if src_ip else [],
    }
    try:
        r = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            json=payload,
            headers={"Authorization": f"Bearer {THEHIVE_KEY}", "Content-Type": "application/json"},
            timeout=10,
        )
        return r.status_code in (200, 201)
    except Exception as e:
        log.error(f"TheHive create alert error: {e}")
        return False


# ── Enrich + Update Document ──────────────────────────────────
def enrich_document(es: Elasticsearch, hit: dict, dry_run: bool) -> dict:
    doc_id  = hit["_id"]
    doc     = hit["_source"]
    index   = hit["_index"]

    src_ip       = doc.get("source", {}).get("ip", "")
    action       = doc.get("event", {}).get("action", "")
    finding_type = (doc.get("aws", {}).get("guardduty", {}).get("finding_type", "")
                    or doc.get("azure", {}).get("securityalert", {}).get("alert_name", ""))
    severity     = int(doc.get("event", {}).get("severity", 5))
    account_id   = doc.get("cloud", {}).get("account", {}).get("id", "")
    env_tag      = next((t for t in doc.get("tags", []) if t in ASSET_VALUE), "lab")

    geo       = geoip_lookup(src_ip)
    abuse     = check_abuseipdb(src_ip)
    mitre     = map_mitre(action, finding_type)
    acct_name = get_aws_account_name(account_id)
    risk      = calculate_risk_score(
        severity,
        abuse.get("score", 0),
        abuse.get("is_tor", False),
        geo.get("is_proxy", False),
        env_tag,
    )

    enrichment = {
        "ip_reputation":  abuse,
        "geoip":          geo,
        "account_name":   acct_name,
        "mitre":          mitre,
        "risk_score":     risk,
        "enriched_at":    datetime.now(timezone.utc).isoformat(),
    }

    if not dry_run:
        es.update(
            index=index,
            id=doc_id,
            body={"doc": {"enrichment": enrichment, "labels": {"risk_score": str(risk)}}},
            retry_on_conflict=3,
        )
        if risk >= RISK_THRESHOLD:
            doc["enrichment"] = enrichment
            created = create_thehive_alert(doc, risk)
            if created:
                log.info(f"TheHive alert created for doc {doc_id} (risk={risk})")

    return enrichment


# ── Fetch Unenriched Alerts ───────────────────────────────────
def fetch_unenriched(es: Elasticsearch, lookback_minutes: int = 60) -> list:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{lookback_minutes}m"}}},
                    {"terms": {"event.kind": ["alert", "event"]}},
                ],
                "must_not": [
                    {"exists": {"field": "enrichment.enriched_at"}}
                ],
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "size": 200,
    }
    result = es.search(index=f"{ELASTIC_INDEX}*", body=query)
    return result["hits"]["hits"]


# ── Main ──────────────────────────────────────────────────────
def run(es: Elasticsearch, args) -> None:
    log.info("─" * 60)
    log.info(f"[Enricher cycle] {datetime.now(timezone.utc).isoformat()}")

    hits = fetch_unenriched(es, lookback_minutes=args.lookback)
    log.info(f"Found {len(hits)} unenriched alert(s)")

    if not hits:
        return

    table = Table(title="Enrichment Results", show_header=True)
    table.add_column("Action",      style="cyan",   max_width=30)
    table.add_column("Source IP",   style="yellow", max_width=18)
    table.add_column("Country",     style="white",  max_width=12)
    table.add_column("AbuseScore",  style="red",    max_width=10, justify="right")
    table.add_column("MITRE",       style="green",  max_width=12)
    table.add_column("RiskScore",   style="bold",   max_width=10, justify="right")

    for hit in hits:
        enrichment = enrich_document(es, hit, dry_run=args.dry_run)
        src        = hit["_source"]
        risk       = enrichment.get("risk_score", 0)
        color      = "red" if risk >= 70 else "yellow" if risk >= 40 else "green"
        table.add_row(
            src.get("event", {}).get("action", "")[:30],
            src.get("source", {}).get("ip", "N/A"),
            enrichment.get("geoip", {}).get("country", "N/A"),
            str(enrichment.get("ip_reputation", {}).get("score", "N/A")),
            enrichment.get("mitre", {}).get("technique", "N/A"),
            f"[{color}]{risk}[/{color}]",
        )
        time.sleep(float(os.getenv("RATE_LIMIT_DELAY_SECONDS", 1)))

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Cloud Alert Enricher")
    parser.add_argument("--mode",      choices=["continuous", "once"], default="once")
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--lookback",  type=int, default=60, help="Minutes to look back for unenriched alerts")
    parser.add_argument("--verbose",   action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.rule("[bold cyan]Cloud Alert Enricher[/bold cyan]")
    log.info(f"Index     : {ELASTIC_INDEX}")
    log.info(f"Mode      : {args.mode}")
    log.info(f"Risk Threshold for TheHive: {RISK_THRESHOLD}")

    es = get_es()

    if args.mode == "once":
        run(es, args)
        return

    run(es, args)
    while True:
        time.sleep(POLL_INTERVAL)
        run(es, args)


if __name__ == "__main__":
    main()
