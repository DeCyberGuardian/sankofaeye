#!/usr/bin/env python3
"""
sankofaeye_bridge.py — SankofahEye → Aegis-INT Intelligence Bridge
====================================================================
Converts SankofahEye passive recon JSON findings into Aegis-INT
pipeline events and submits them for DRIB production.

Usage:
    python scripts/sankofaeye_bridge.py \
        --json reports/SankofahEye_domain_20260529.json \
        --aegis-url http://172.20.10.10 \
        --token aegis-dev-key-001

Author: DeCyberGuardian | AfriWealth Cyber Intelligence
"""
import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


# ── MITRE technique mapping from SankofahEye finding types ────────────────
FINDING_TECHNIQUE_MAP = {
    "exposed_services":     "T1133",   # External Remote Services
    "credential_exposure":  "T1078",   # Valid Accounts
    "momo_exposure":        "T1190",   # Exploit Public-Facing Application
    "wa_intel":             "T1566",   # Phishing (threat actor targeting)
    "dns_security":         "T1566.001", # Spearphishing (email spoofing risk)
    "subdomains":           "T1595",   # Active Scanning (attack surface)
    "reputation":           "T1071",   # C2 (malicious reputation indicator)
    "dark_web":             "T1594",   # Search Victim-Owned Websites
    "infostealer_exposure": "T1555",   # Credentials from Password Stores
    "tech_fingerprint":     "T1190",   # Exploit Public-Facing Application
}

SEVERITY_MAP = {
    "CRITICAL": 15,
    "HIGH":     12,
    "MEDIUM":   8,
    "LOW":      5,
    "INFO":     3,
}


def load_sankofah_json(path: str) -> dict:
    """Load and validate SankofahEye JSON findings file."""
    p = Path(path)
    if not p.exists():
        # Try glob expansion
        matches = list(Path(".").glob(path))
        if not matches:
            print(f"❌ File not found: {path}")
            sys.exit(1)
        p = sorted(matches)[-1]
        print(f"  Using: {p}")

    with open(p) as f:
        data = json.load(f)

    if "findings" not in data:
        print("❌ Invalid SankofahEye JSON — missing 'findings' key")
        sys.exit(1)

    return data


def findings_to_events(data: dict) -> list[dict]:
    """Convert SankofahEye findings dict into Aegis-INT RawEvent list."""
    findings = data["findings"]
    scoring  = data.get("scoring", {})
    target   = findings.get("target", "unknown")
    ts       = datetime.now(timezone.utc).isoformat()
    events   = []

    risk_rating = scoring.get("risk_rating", "MEDIUM")
    base_sev    = SEVERITY_MAP.get(risk_rating, 8)

    # ── Exposed services ──────────────────────────────────────────────────
    for svc in findings.get("exposed_services", []):
        events.append({
            "source": "sankofah_passive",
            "raw_payload": {
                "scan_type":        "passive_recon",
                "target":           target,
                "finding_type":     "exposed_service",
                "port":             svc.get("port"),
                "service":          svc.get("service", "unknown"),
                "banner":           svc.get("banner", ""),
                "severity":         base_sev + 2,
                "mitre_technique":  FINDING_TECHNIQUE_MAP["exposed_services"],
                "timestamp":        ts,
                "source_tool":      "SankofahEye/Censys",
                "agent_name":       f"sankofah-{target}",
                "rule_desc":        f"Exposed {svc.get('service','service')} on {target}:{svc.get('port','')}",
            }
        })

    # ── Credential exposure ───────────────────────────────────────────────
    cred = findings.get("credential_exposure", {})
    if cred.get("breached_accounts", 0) > 0:
        events.append({
            "source": "sankofah_passive",
            "raw_payload": {
                "scan_type":        "passive_recon",
                "target":           target,
                "finding_type":     "credential_exposure",
                "breached_count":   cred.get("breached_accounts", 0),
                "sources":          cred.get("sources", []),
                "severity":         base_sev + 3,
                "mitre_technique":  FINDING_TECHNIQUE_MAP["credential_exposure"],
                "timestamp":        ts,
                "source_tool":      "SankofahEye/HIBP",
                "agent_name":       f"sankofah-{target}",
                "rule_desc":        f"{cred.get('breached_accounts',0)} breached accounts found for {target}",
            }
        })

    # ── Mobile Money exposure ─────────────────────────────────────────────
    momo = findings.get("momo_exposure", {})
    for mf in momo.get("findings", []):
        sev = SEVERITY_MAP.get(mf.get("severity", "HIGH"), 12)
        events.append({
            "source": "sankofah_passive",
            "raw_payload": {
                "scan_type":        "passive_recon",
                "target":           target,
                "finding_type":     "momo_exposure",
                "pattern":          mf.get("pattern", ""),
                "momo_severity":    mf.get("severity", "HIGH"),
                "severity":         sev,
                "mitre_technique":  FINDING_TECHNIQUE_MAP["momo_exposure"],
                "timestamp":        ts,
                "source_tool":      "SankofahEye/MoMoModule",
                "agent_name":       f"sankofah-{target}",
                "rule_desc":        f"Mobile Money exposure: {mf.get('pattern','')} [{mf.get('severity','')}]",
            }
        })

    # ── West Africa threat intel match ────────────────────────────────────
    wa = findings.get("wa_intel", {})
    for actor in wa.get("matched_actors", []):
        events.append({
            "source": "sankofah_passive",
            "raw_payload": {
                "scan_type":        "passive_recon",
                "target":           target,
                "finding_type":     "threat_actor_match",
                "threat_actor":     actor,
                "sector":           wa.get("sector", "Unknown"),
                "severity":         base_sev + 4,
                "mitre_technique":  FINDING_TECHNIQUE_MAP["wa_intel"],
                "timestamp":        ts,
                "source_tool":      "SankofahEye/WAThreatDB",
                "agent_name":       f"sankofah-{target}",
                "rule_desc":        f"Threat actor {actor} — sector relevance match for {target}",
            }
        })

    # ── DNS / email security failures ─────────────────────────────────────
    dns = findings.get("dns_security", {})
    dns_issues = []
    if dns.get("spf")   in ("fail", "missing", "none"):
        dns_issues.append("SPF misconfiguration")
    if dns.get("dmarc") in ("fail", "missing", "none"):
        dns_issues.append("DMARC not enforced")
    if dns.get("dkim")  in ("fail", "missing", "none"):
        dns_issues.append("DKIM not configured")

    if dns_issues:
        events.append({
            "source": "sankofah_passive",
            "raw_payload": {
                "scan_type":        "passive_recon",
                "target":           target,
                "finding_type":     "dns_security",
                "issues":           dns_issues,
                "spf":              dns.get("spf", "unknown"),
                "dmarc":            dns.get("dmarc", "unknown"),
                "dkim":             dns.get("dkim", "unknown"),
                "severity":         base_sev,
                "mitre_technique":  FINDING_TECHNIQUE_MAP["dns_security"],
                "timestamp":        ts,
                "source_tool":      "SankofahEye/DNSModule",
                "agent_name":       f"sankofah-{target}",
                "rule_desc":        f"Email security gaps on {target}: {', '.join(dns_issues)}",
            }
        })

    # ── Infostealer exposure ──────────────────────────────────────────────
    info = findings.get("infostealer_exposure", {})
    if info.get("exposed", False) or info.get("count", 0) > 0:
        events.append({
            "source": "sankofah_passive",
            "raw_payload": {
                "scan_type":        "passive_recon",
                "target":           target,
                "finding_type":     "infostealer_exposure",
                "count":            info.get("count", 1),
                "severity":         base_sev + 3,
                "mitre_technique":  FINDING_TECHNIQUE_MAP["infostealer_exposure"],
                "timestamp":        ts,
                "source_tool":      "SankofahEye/HudsonRock",
                "agent_name":       f"sankofah-{target}",
                "rule_desc":        f"Infostealer credential exposure detected for {target}",
            }
        })

    return events


def submit_to_aegis(events: list[dict], aegis_url: str, token: str) -> dict:
    """POST events to Aegis-INT /api/pipeline/ingest."""
    url  = f"{aegis_url.rstrip('/')}/api/pipeline/ingest"
    body = json.dumps({"events": events}).encode()

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"❌ HTTP {e.code}: {body}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"❌ Connection failed: {e.reason}")
        print(f"   Is Aegis-INT running at {aegis_url}?")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="SankofahEye → Aegis-INT Intelligence Bridge"
    )
    parser.add_argument("--json",      required=True, help="Path to SankofahEye JSON findings file")
    parser.add_argument("--aegis-url", default="http://172.20.10.10", help="Aegis-INT base URL")
    parser.add_argument("--token",     default="aegis-dev-key-001",   help="Aegis-INT API token")
    parser.add_argument("--dry-run",   action="store_true", help="Print events without submitting")
    args = parser.parse_args()

    print("=" * 60)
    print("  SankofahEye → Aegis-INT Bridge")
    print("  AfriWealth Cyber Intelligence")
    print("=" * 60)

    # Load findings
    print(f"\n[1/3] Loading SankofahEye findings: {args.json}")
    data   = load_sankofah_json(args.json)
    target = data["findings"].get("target", "unknown")
    score  = data.get("scoring", {})
    print(f"  Target:      {target}")
    print(f"  Risk:        {score.get('risk_rating','?')} ({score.get('risk_score','?')}/100)")
    print(f"  Findings:    {score.get('finding_count','?')}")

    # Convert to events
    print("\n[2/3] Converting findings to Aegis-INT pipeline events...")
    events = findings_to_events(data)
    print(f"  Events generated: {len(events)}")
    for evt in events:
        rp = evt["raw_payload"]
        print(f"    · [{rp.get('mitre_technique','?')}] {rp.get('rule_desc','')[:70]}")

    if args.dry_run:
        print("\n[DRY RUN] Events not submitted.")
        print(json.dumps({"events": events}, indent=2))
        return

    if not events:
        print("\n⚠️  No events generated — check findings structure")
        sys.exit(0)

    # Submit to Aegis-INT
    print(f"\n[3/3] Submitting to Aegis-INT at {args.aegis_url}...")
    result = submit_to_aegis(events, args.aegis_url, args.token)

    print("\n" + "=" * 60)
    print("  ✅ Pipeline run queued")
    print(f"  object_id:  {result.get('object_id','?')}")
    print(f"  status:     {result.get('status','?')}")
    print(f"  events:     {result.get('event_count','?')}")
    print(f"\n  Poll:  GET {args.aegis_url}/api/pipeline/status/{result.get('object_id','?')}")
    print(f"  Watch: http://172.20.10.10 (Live DRIB Feed)")
    print("=" * 60)


if __name__ == "__main__":
    main()
