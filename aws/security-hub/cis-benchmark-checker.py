#!/usr/bin/env python3
"""
cis-benchmark-checker.py
Queries Security Hub for CIS Benchmark findings, calculates compliance
percentages per section, and generates a markdown report.
"""

import os
import json
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

import boto3
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

load_dotenv()
console = Console()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger("cis-benchmark-checker")

REGION     = os.getenv("AWS_DEFAULT_REGION", "ca-central-1")
REPORT_DIR = Path("compliance/cis-benchmarks")

CIS_SECTIONS = {
    "1": "Identity and Access Management",
    "2": "Storage",
    "3": "Logging",
    "4": "Monitoring",
    "5": "Networking",
}


def get_sh_client():
    return boto3.client("securityhub", region_name=REGION)


def fetch_cis_findings(sh_client) -> list:
    all_findings = []
    paginator = sh_client.get_paginator("get_findings")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
        task = p.add_task("Fetching CIS benchmark findings…", total=None)
        pages = paginator.paginate(
            Filters={
                "GeneratorId": [
                    {"Value": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark", "Comparison": "PREFIX"},
                    {"Value": "cis-aws-foundations-benchmark", "Comparison": "PREFIX"},
                ],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            },
        )
        for page in pages:
            all_findings.extend(page.get("Findings", []))
        p.update(task, description=f"Fetched {len(all_findings)} CIS findings.")
    return all_findings


def categorise_findings(findings: list) -> dict:
    """Categorise findings by CIS section and compliance status."""
    sections = defaultdict(lambda: {"PASSED": 0, "FAILED": 0, "WARNING": 0, "UNKNOWN": 0, "findings": []})

    for f in findings:
        gen_id  = f.get("GeneratorId", "")
        # Extract CIS control number e.g. "cis-aws-foundations-benchmark/v/1.4.0/1.1"
        parts   = gen_id.split("/")
        control = parts[-1] if parts else "0.0"
        section = control.split(".")[0] if "." in control else "0"

        status = f.get("Compliance", {}).get("Status", "UNKNOWN")
        sections[section][status] += 1
        sections[section]["findings"].append({
            "control":     control,
            "title":       f.get("Title", ""),
            "status":      status,
            "severity":    f.get("Severity", {}).get("Label", "INFORMATIONAL"),
            "description": f.get("Description", ""),
            "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
        })

    return sections


def calculate_section_compliance(section_data: dict) -> float:
    passed = section_data.get("PASSED", 0)
    failed = section_data.get("FAILED", 0)
    total  = passed + failed
    return round(passed / total * 100, 1) if total > 0 else 0.0


def print_compliance_table(sections: dict):
    table = Table(title=f"CIS AWS Foundations Benchmark — {REGION}", show_header=True)
    table.add_column("Section", style="cyan", width=8)
    table.add_column("Name",    style="white", width=40)
    table.add_column("PASS",    style="green", justify="right")
    table.add_column("FAIL",    style="red",   justify="right")
    table.add_column("WARN",    style="yellow", justify="right")
    table.add_column("%",       style="bold",  justify="right")

    for sec_num in sorted(sections.keys(), key=lambda x: int(x) if x.isdigit() else 99):
        sec  = sections[sec_num]
        name = CIS_SECTIONS.get(sec_num, f"Section {sec_num}")
        pct  = calculate_section_compliance(sec)
        color = "green" if pct >= 80 else "yellow" if pct >= 60 else "red"
        table.add_row(
            sec_num,
            name,
            str(sec.get("PASSED", 0)),
            str(sec.get("FAILED", 0)),
            str(sec.get("WARNING", 0)),
            f"[{color}]{pct}%[/{color}]",
        )

    console.print(table)


def generate_markdown_report(sections: dict, findings: list) -> str:
    now       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_pass = sum(s.get("PASSED", 0) for s in sections.values())
    total_fail = sum(s.get("FAILED", 0) for s in sections.values())
    total_all  = total_pass + total_fail
    overall    = round(total_pass / total_all * 100, 1) if total_all > 0 else 0

    lines = [
        "# CIS AWS Foundations Benchmark Compliance Report",
        "",
        f"**Generated:** {now}  ",
        f"**Region:** {REGION}  ",
        f"**Standard:** CIS AWS Foundations Benchmark v1.4.0  ",
        f"**Overall Compliance:** {overall}% ({total_pass}/{total_all} controls passing)",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Controls Evaluated | {total_all} |",
        f"| Controls Passing | {total_pass} |",
        f"| Controls Failing | {total_fail} |",
        f"| Overall Compliance | {overall}% |",
        "",
        "---",
        "",
        "## Results by Section",
        "",
    ]

    for sec_num in sorted(sections.keys(), key=lambda x: int(x) if x.isdigit() else 99):
        sec   = sections[sec_num]
        name  = CIS_SECTIONS.get(sec_num, f"Section {sec_num}")
        pct   = calculate_section_compliance(sec)
        status_icon = "✅" if pct >= 80 else "⚠️" if pct >= 60 else "❌"

        lines += [
            f"### {status_icon} Section {sec_num}: {name}",
            "",
            f"**Compliance:** {pct}% | "
            f"PASS: {sec.get('PASSED',0)} | "
            f"FAIL: {sec.get('FAILED',0)} | "
            f"WARN: {sec.get('WARNING',0)}",
            "",
        ]

        failed_findings = [f for f in sec.get("findings", []) if f["status"] == "FAILED"]
        if failed_findings:
            lines += ["**Failed Controls:**", ""]
            for ff in sorted(failed_findings, key=lambda x: x["control"]):
                lines += [
                    f"#### Control {ff['control']}: {ff['title']}",
                    f"- **Severity:** {ff['severity']}",
                    f"- **Status:** {ff['status']}",
                    f"- **Description:** {ff['description']}",
                    f"- **Remediation:** {ff['remediation']}",
                    "",
                ]

    lines += [
        "---",
        "",
        "## Remediation Roadmap",
        "",
        "Priority order for remediation based on severity and section:",
        "",
    ]

    all_failed = [
        f for sec in sections.values()
        for f in sec.get("findings", [])
        if f["status"] == "FAILED"
    ]
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    all_failed.sort(key=lambda x: sev_order.get(x["severity"], 5))

    for i, ff in enumerate(all_failed[:20], 1):
        lines.append(f"{i}. **[{ff['severity']}]** Control {ff['control']}: {ff['title']}")

    lines += [
        "",
        "---",
        "",
        "*Report generated by cis-benchmark-checker.py — 06-cloud-soc-canada*",
    ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="CIS Benchmark Compliance Checker")
    parser.add_argument("--output", default=None, help="Output markdown file path")
    args = parser.parse_args()

    console.rule("[bold cyan]CIS Benchmark Checker[/bold cyan]")
    log.info(f"Region: {REGION}")

    sh_client = get_sh_client()
    findings  = fetch_cis_findings(sh_client)

    if not findings:
        log.warning("No CIS findings returned. Is Security Hub enabled with CIS standard?")
        return

    sections = categorise_findings(findings)
    print_compliance_table(sections)

    report_md = generate_markdown_report(sections, findings)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = args.output or REPORT_DIR / f"cis-compliance-{datetime.now().strftime('%Y%m%d-%H%M')}.md"
    with open(output_path, "w") as f:
        f.write(report_md)

    log.info(f"Report saved: {output_path}")
    console.rule("[bold green]Done[/bold green]")


if __name__ == "__main__":
    main()
