#!/usr/bin/env python3
"""
SankofahEye — Main Orchestrator
AfriWealth Cyber Intelligence

Passive Reconnaissance & Exposure Scanning Platform
Usage: python sankofaeye.py --domain example.com [--output ./output]
"""

import argparse
import json
import os
import sys
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dotenv import load_dotenv

# Load .env before anything else
load_dotenv()

from utils.logger import SankofahLogger
from utils.validator import validate_domain
from utils.aggregator import aggregate
from utils.risk_scorer import score

import modules.subfinder_module  as subfinder_mod
import modules.harvester_module  as harvester_mod
import modules.censys_module     as censys_mod
import modules.hibp_module       as hibp_mod
import modules.vt_urlscan_module as vt_urlscan_mod
import modules.darkweb_module    as darkweb_mod
import modules.hudsonrock_module as hudsonrock_mod
import modules.dns_module        as dns_mod
import modules.ssl_module        as ssl_mod
from reports.pdf_generator import generate as generate_pdf
from utils.compliance_mapper import map_compliance
from reports.executive_onepager import generate as generate_exec_onepager


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def report_only(json_path: str, config: dict, output_dir: str) -> None:
    """
    Regenerate PDF reports from an existing JSON findings file.
    No rescan is performed — useful for analyst edits and report re-runs.

    Usage:
        python sankofaeye.py --report-only output/SankofahEye_ghipss.com_20260527.json
    """
    log = SankofahLogger("sankofaeye")

    if not os.path.exists(json_path):
        log.error(f"[report-only] JSON file not found: {json_path}")
        sys.exit(1)

    log.info(f"[report-only] Loading findings from {json_path}")

    with open(json_path, "r") as f:
        data = json.load(f)

    findings = data.get("findings")
    scoring  = data.get("scoring")

    if not findings or not scoring:
        log.error("[report-only] JSON missing 'findings' or 'scoring' keys")
        sys.exit(1)

    target = findings.get("target", "unknown")
    log.info(f"[report-only] Target: {target} | Score: {scoring['score']}/100 {scoring['rating'].upper()}")

    os.makedirs(output_dir, exist_ok=True)

    pdf_path = generate_pdf(findings, scoring, config, output_dir)
    log.info(f"[report-only] Full report:       {pdf_path}")

    try:
        exec_path = generate_exec_onepager(findings, scoring, config, output_dir)
        log.info(f"[report-only] Executive summary: {exec_path}")
    except Exception as e:
        log.warning(f"[report-only] Executive one-pager skipped: {e}")

    log.info("[report-only] Done.")



def run_scan(domain: str, config: dict, output_dir: str) -> str:
    """
    Full scan pipeline. Returns path to generated PDF.
    """
    log = SankofahLogger(
        "sankofaeye",
        log_dir=config["output"]["log_directory"],
        level=config["output"]["log_level"],
    )
    log.banner(domain, config["brand"]["version"])

    modules_cfg  = config.get("modules", {})
    timeouts_cfg = config.get("timeouts", {})

    # ── Default results ───────────────────────────────────────
    results = {
        "subfinder": {
            "module": "subfinder", "subdomains": [], "count": 0,
            "status": "skipped", "error": None,
        },
        "harvester": {
            "module": "theharvester", "emails": [], "hosts": [], "ips": [],
            "status": "skipped", "error": None,
        },
        "shodan": {
            "module": "censys", "hosts": [], "open_ports": [],
            "high_risk_ports": [], "cves": [],
            "status": "skipped", "error": None,
        },
        "hibp": {
            "module": "hibp", "breached_accounts": [], "breach_summary": [],
            "total_breaches": 0, "status": "skipped", "error": None,
        },
        "vt_urlscan": {
            "module": "vt_urlscan", "virustotal": {}, "urlscan": {},
            "status": "skipped", "error": None,
        },
        "darkweb": {
            "module": "darkweb", "mentions": [], "total_mentions": 0,
            "high_risk_mentions": 0, "status": "skipped", "error": None,
        },
        "hudsonrock": {
            "module": "hudsonrock", "compromised_employees": [],
            "compromised_users": [], "stealer_families": [],
            "total_employees": 0, "total_users": 0,
            "status": "skipped", "error": None,
        },
        "dns": {
            "module": "dns", "spf": {}, "dmarc": {}, "dkim": {},
            "mx": {}, "ns": {}, "issues": [],
            "status": "skipped", "error": None,
        },
        "ssl": {
            "module": "ssl", "certificates": [], "expired": [],
            "expiring_soon": [], "self_signed": [], "weak_protocol": [],
            "unreachable_https": [], "total_checked": 0,
            "total_issues": 0, "status": "skipped", "error": None,
        },
    }

    # ── Build parallel module map ─────────────────────────────
    module_map = {}

    if modules_cfg.get("subfinder", True):
        module_map["subfinder"] = (
            subfinder_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("subfinder", 60)},
        )
    if modules_cfg.get("theharvester", True):
        module_map["harvester"] = (
            harvester_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("theharvester", 120)},
        )
    if modules_cfg.get("shodan", True):
        module_map["shodan"] = (
            censys_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("shodan", 30)},
        )
    if modules_cfg.get("hibp", True):
        module_map["hibp"] = (
            hibp_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("hibp", 20)},
        )
    if modules_cfg.get("virustotal", True) or modules_cfg.get("urlscan", True):
        module_map["vt_urlscan"] = (
            vt_urlscan_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("virustotal", 30)},
        )
    if modules_cfg.get("darkweb", True):
        module_map["darkweb"] = (
            darkweb_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("darkweb", 45)},
        )
    if modules_cfg.get("hudsonrock", True):
        module_map["hudsonrock"] = (
            hudsonrock_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("hudsonrock", 30)},
        )
    if modules_cfg.get("dns", True):
        module_map["dns"] = (
            dns_mod.run, (domain,),
            {"timeout": timeouts_cfg.get("dns", 30)},
        )


    # ── Run parallel modules ──────────────────────────────────
    log.info(f"Running {len(module_map)} module(s) in parallel...")

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_key = {
            executor.submit(fn, *args, **kwargs): key
            for key, (fn, args, kwargs) in module_map.items()
        }
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
            except Exception as e:
                log.error(f"Module [{key}] raised an exception: {e}")

    # ── HIBP re-run with harvested emails ─────────────────────
    if modules_cfg.get("hibp", True) and results["harvester"].get("emails"):
        results["hibp"] = hibp_mod.run(
            domain,
            emails=results["harvester"]["emails"],
            timeout=timeouts_cfg.get("hibp", 20),
        )

    # ── SSL runs after parallel so subfinder results exist ────
    if modules_cfg.get("ssl", True):
        log.info("[SSL] Running certificate checks...")
        results["ssl"] = ssl_mod.run(
            domain,
            subdomains=results["subfinder"].get("subdomains", []),
            timeout=timeouts_cfg.get("ssl", 45),
        )

    # ── Aggregate ─────────────────────────────────────────────
    findings = aggregate(
        subfinder=results["subfinder"],
        harvester=results["harvester"],
        shodan=results["shodan"],
        hibp=results["hibp"],
        vt_urlscan=results["vt_urlscan"],
        darkweb=results["darkweb"],
        hudsonrock=results["hudsonrock"],
        dns=results["dns"],
        ssl=results["ssl"],
        target=domain,
    )

    # ── Score ─────────────────────────────────────────────────
    risk_weights = config.get("risk_weights", {})
    scoring = score(findings, risk_weights)

    # ── Save JSON dump ────────────────────────────────────────
    if config["output"].get("json_dump", True):
        os.makedirs(output_dir, exist_ok=True)
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(output_dir, f"SankofahEye_{domain}_{ts}.json")
        with open(json_path, "w") as jf:
            json.dump({"findings": findings, "scoring": scoring}, jf, indent=2)
        log.info(f"Raw findings saved → {json_path}")

    # ── Compliance mapping (runs after scoring) ───────────────
    findings['compliance'] = map_compliance(findings, scoring)

    # ── Generate PDF ──────────────────────────────────────────
    pdf_path = None
    if config["output"].get("pdf_report", True):
        pdf_path = generate_pdf(findings, scoring, config, output_dir)

    # ── Generate Executive One-Pager ──────────────────────────
    # Auto-generated alongside every scan. Single-page plain-English
    # summary for CISO, board, and non-technical decision-makers.
    exec_path = None
    try:
        exec_path = generate_exec_onepager(findings, scoring, config, output_dir)
    except Exception as _e:
        log.warning(f"Executive one-pager skipped: {_e}")

    log.info("=" * 60)
    log.info(f"Scan complete. Risk: {scoring['rating'].upper()} ({scoring['score']}/100)")
    log.info(f"Findings: {scoring['finding_count']}")
    if pdf_path:
        log.info(f"Full report:        {pdf_path}")
    if exec_path:
        log.info(f"Executive summary:  {exec_path}")
    log.info("=" * 60)

    return pdf_path


def main():
    parser = argparse.ArgumentParser(
        description="SankofahEye — AfriWealth Passive Exposure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sankofaeye.py --domain gcb.com.gh
  python sankofaeye.py --domain mtn.com.gh bog.gov.gh --output ./reports
  python sankofaeye.py --domain example.com --config config.yaml
        """
    )
    parser.add_argument(
        "--domain", required=False, nargs="+",
        help="Target domain(s) to scan",
    )
    parser.add_argument(
        "--output", default="output",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config file",
    )
    parser.add_argument(
        "--report-only", dest="report_only", default=None, metavar="JSON_PATH",
        help="Regenerate PDF reports from an existing JSON findings file — no rescan",
    )
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"[ERROR] Config file not found: {args.config}")
        sys.exit(1)

    config = load_config(args.config)

    # ── --report-only mode ────────────────────────────────────
    if args.report_only:
        report_only(args.report_only, config, args.output)
        return

    # ── Normal scan mode ──────────────────────────────────────
    if not args.domain:
        print("[ERROR] --domain is required unless --report-only is used")
        sys.exit(1)

    for raw_domain in args.domain:
        valid, domain = validate_domain(raw_domain)
        if not valid:
            print(f"[ERROR] Invalid domain: {raw_domain} — skipping")
            continue
        run_scan(domain, config, args.output)


if __name__ == "__main__":
    main()