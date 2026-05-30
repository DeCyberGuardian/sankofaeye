#!/usr/bin/env python3
"""
aegis_push.py — Auto-push SankofahEye findings to Aegis-INT
=============================================================
Usage (auto — set env vars, runs after scan):
    AEGIS_INT_URL=http://172.20.10.10 \
    AEGIS_INT_TOKEN=aegis-dev-key-001 \
    python sankofaeye.py --domain gcb.com.gh

Usage (manual CLI):
    python aegis_integration/aegis_push.py \
        --json reports/SankofahEye_gcb.com.gh_20260529.json

Author: DeCyberGuardian | AfriWealth Cyber Intelligence
"""
import argparse
from curses import echo
import json
import os
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class AegisPushConfig:
    url:     str  = field(default_factory=lambda: os.environ.get("AEGIS_INT_URL", "http://172.20.10.10"))
    token:   str  = field(default_factory=lambda: os.environ.get("AEGIS_INT_TOKEN", "aegis-dev-key-001"))
    enabled: bool = field(default_factory=lambda: bool(os.environ.get("AEGIS_INT_URL")))
    timeout: int  = 30

    def __post_init__(self):
        self.url = self.url.rstrip("/")


TECHNIQUE_MAP = {
    "exposed_services":     "T1133",
    "credential_exposure":  "T1078",
    "momo_exposure":        "T1190",
    "wa_intel":             "T1566",
    "dns_security":         "T1566.001",
    "subdomains":           "T1595",
    "reputation":           "T1071",
    "dark_web":             "T1594",
    "infostealer_exposure": "T1555",
    "tech_fingerprint":     "T1190",
}

SEVERITY_MAP = {"CRITICAL": 15, "HIGH": 12, "MEDIUM": 8, "LOW": 5, "INFO": 3}


def _findings_to_events(data: dict) -> list[dict]:
    findings = data["findings"]
    scoring  = data.get("scoring", {})
    target   = findings.get("target", "unknown")
    ts       = datetime.now(timezone.utc).isoformat()
    base_sev = SEVERITY_MAP.get(scoring.get("rating", "MEDIUM").upper(), 8)
    events   = []

    def evt(ftype: str, desc: str, sev: int, extra: dict = None) -> dict:
        payload = {
            "scan_type":       "passive_recon",
            "target":          target,
            "finding_type":    ftype,
            "severity":        sev,
            "mitre_technique": TECHNIQUE_MAP.get(ftype, "T1595"),
            "timestamp":       ts,
            "source_tool":     "SankofahEye",
            "agent_name":      f"sankofah-{target}",
            "rule_desc":       desc,
            "risk_score":      scoring.get("score", 0),
        }
        if extra:
            payload.update(extra)
        return {"source": "manual", "payload": payload}

    # ── Exposed services ──────────────────────────────────────────────────
    # Structure: exposed_services.high_risk_ports = [str, ...]
    #            exposed_services.hosts = [str, ...]
    svc_data = findings.get("exposed_services", {})
    for port in svc_data.get("high_risk_ports", []):
        events.append(evt(
            "exposed_services",
            f"High-risk port exposed on {target}: {port}",
            base_sev + 2,
            {"port": port},
        ))
    for cve in svc_data.get("cves", []):
        events.append(evt(
            "exposed_services",
            f"CVE risk on {target}: {cve}",
            base_sev + 3,
            {"cve": cve},
        ))

    # ── Credential exposure ───────────────────────────────────────────────
    # Structure: credential_exposure.total_breached = int
    cred = findings.get("credential_exposure", {})
    total_breached = cred.get("total_breached", 0)
    if total_breached > 0:
        events.append(evt(
            "credential_exposure",
            f"{total_breached} breached accounts found for {target}",
            base_sev + 3,
            {
                "breached_count": total_breached,
                "breach_names":   cred.get("breach_names", []),
            },
        ))

    # ── Mobile Money exposure ─────────────────────────────────────────────
    # Structure: momo_exposure.exposed_services = [{subdomain, pattern, service_name, ...}]
    momo = findings.get("momo_exposure", {})
    for mf in momo.get("exposed_services", []):
        severity_str = mf.get("severity", "HIGH")
        sev = SEVERITY_MAP.get(severity_str, 12)
        events.append(evt(
            "momo_exposure",
            f"MoMo exposure: {mf.get('subdomain','')} [{mf.get('pattern','')}] — {severity_str}",
            sev,
            {
                "subdomain":    mf.get("subdomain"),
                "pattern":      mf.get("pattern"),
                "service_name": mf.get("service_name"),
                "operator":     momo.get("operator"),
            },
        ))

    # ── West Africa threat actors ─────────────────────────────────────────
    # Structure: wa_intel.relevant_actors = [{id, name, relevance, motivation, ...}]
    wa = findings.get("wa_intel", {})
    for actor in wa.get("relevant_actors", []):
        relevance = actor.get("relevance", "MEDIUM")
        sev = SEVERITY_MAP.get(relevance, 8)
        events.append(evt(
            "wa_intel",
            f"Threat actor: {actor.get('name','')} [{relevance}] — {actor.get('motivation','')}",
            sev,
            {
                "actor_id":   actor.get("id"),
                "actor_name": actor.get("name"),
                "relevance":  relevance,
                "motivation": actor.get("motivation"),
            },
        ))

    # ── DNS / email security ──────────────────────────────────────────────
    # Structure: dns_security.spf = {present, valid, issues:[str]}
    dns = findings.get("dns_security", {})
    dns_issues = []
    for proto in ("spf", "dmarc", "dkim"):
        rec = dns.get(proto, {})
        if isinstance(rec, dict) and not rec.get("valid", True):
            dns_issues.extend(rec.get("issues", [f"{proto.upper()} misconfigured"]))
    if dns_issues:
        events.append(evt(
            "dns_security",
            f"Email security gaps on {target}: {'; '.join(dns_issues[:3])}",
            base_sev,
            {"issues": dns_issues},
        ))

    # ── Infostealer exposure ──────────────────────────────────────────────
    # Structure: infostealer_exposure.total_employees + total_users
    info = findings.get("infostealer_exposure", {})
    total_info = info.get("total_employees", 0) + info.get("total_users", 0)
    if total_info > 0:
        events.append(evt(
            "infostealer_exposure",
            f"Infostealer exposure: {total_info} credentials for {target}",
            base_sev + 3,
            {
                "total_employees": info.get("total_employees", 0),
                "total_users":     info.get("total_users", 0),
                "stealer_families": info.get("stealer_families", []),
            },
        ))

    # ── Reputation flags ──────────────────────────────────────────────────
    # Structure: reputation.suspicious_votes, flagged_vendors = [{vendor, result}]
    rep = findings.get("reputation", {})
    flagged = rep.get("flagged_vendors", [])
    if rep.get("malicious_votes", 0) > 0 or rep.get("suspicious_votes", 0) > 0:
        events.append(evt(
            "reputation",
            f"Reputation flags for {target}: {len(flagged)} vendor(s) flagged",
            base_sev + 1,
            {
                "malicious_votes":  rep.get("malicious_votes", 0),
                "suspicious_votes": rep.get("suspicious_votes", 0),
                "flagged_vendors":  [v.get("vendor") for v in flagged],
            },
        ))

    # ── Dark web mentions ─────────────────────────────────────────────────
    # Structure: dark_web.total_mentions = int, high_risk_mentions = int
    dark = findings.get("dark_web", {})
    if dark.get("total_mentions", 0) > 0:
        events.append(evt(
            "dark_web",
            f"Dark web mentions of {target}: {dark.get('total_mentions',0)} total, {dark.get('high_risk_mentions',0)} high-risk",
            base_sev + 2,
            {
                "total_mentions":     dark.get("total_mentions", 0),
                "high_risk_mentions": dark.get("high_risk_mentions", 0),
            },
        ))

    # ── Technology CVE risks ──────────────────────────────────────────────
    # Structure: tech_fingerprint.cve_risks = [{tech, cve_class, ...}]
    tech = findings.get("tech_fingerprint", {})
    for risk in tech.get("cve_risks", []):
        events.append(evt(
            "tech_fingerprint",
            f"Tech CVE risk on {target}: {risk.get('tech','')} — {risk.get('cve_class','')}",
            base_sev + 1,
            {"tech": risk.get("tech"), "cve_class": risk.get("cve_class")},
        ))

    # ── Subdomains (attack surface) ───────────────────────────────────────
    # Structure: subdomains.list = [str], subdomains.count = int
    subs = findings.get("subdomains", {})
    sub_list = subs.get("list", [])
    if len(sub_list) > 5:
        events.append(evt(
            "subdomains",
            f"Large attack surface: {len(sub_list)} subdomains enumerated for {target}",
            base_sev,
            {"count": len(sub_list), "sample": sub_list[:5]},
        ))

    return events


def _submit(events: list[dict], cfg: AegisPushConfig) -> dict:
    url  = f"{cfg.url}/api/pipeline/ingest"
    body = json.dumps({"events": events}).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {cfg.token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode()}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed — is Aegis-INT running at {cfg.url}?") from e


def push_to_aegis(
    json_path: str,
    cfg: "AegisPushConfig | None" = None,
    silent: bool = False,
) -> "dict | None":
    """
    Push SankofahEye JSON findings to Aegis-INT pipeline.
    Returns pipeline response dict, or None if disabled/failed.
    """
    if cfg is None:
        cfg = AegisPushConfig()

    def log(msg):
        if not silent:
            print(f"[Aegis-INT] {msg}")

    if not cfg.enabled:
        log("Push disabled — set AEGIS_INT_URL to enable")
        return None

    try:
        path = Path(json_path)
        if not path.exists():
            log(f"❌ JSON not found: {json_path}")
            return None

        with open(path) as f:
            data = json.load(f)

        if "findings" not in data:
            log("❌ Invalid SankofahEye JSON")
            return None

        target  = data["findings"].get("target", "unknown")
        scoring = data.get("scoring", {})
        log(f"Pushing: {target} — {scoring.get('rating','?')} ({scoring.get('score','?')}/100)")

        events = _findings_to_events(data)
        if not events:
            log("⚠️  No events generated")
            return None

        log(f"Submitting {len(events)} events to {cfg.url}...")
        result = _submit(events, cfg)
        log(f"✅ Pipeline queued — object_id: {result.get('object_id','?')}")
        log(f"   Watch: {cfg.url}")
        return result

    except Exception as exc:
        log(f"❌ Push failed: {exc}")
        return None


def _cli():
    parser = argparse.ArgumentParser(
        description="SankofahEye → Aegis-INT push"
    )
    parser.add_argument("--json",      required=True)
    parser.add_argument("--aegis-url", default=os.environ.get("AEGIS_INT_URL", "http://172.20.10.10"))
    parser.add_argument("--token",     default=os.environ.get("AEGIS_INT_TOKEN", "aegis-dev-key-001"))
    parser.add_argument("--dry-run",   action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print("  SankofahEye → Aegis-INT | AfriWealth Cyber Intelligence")
    print("=" * 60)

    path = Path(args.json)
    if not path.exists():
        print(f"❌ File not found: {args.json}")
        sys.exit(1)

    with open(path) as f:
        data = json.load(f)

    events  = _findings_to_events(data)
    target  = data["findings"].get("target", "unknown")
    scoring = data.get("scoring", {})

    print(f"\nTarget:  {target}")
    print(f"Risk:    {scoring.get('rating','?')} ({scoring.get('score','?')}/100)")
    print(f"Events:  {len(events)}")
    for e in events:
        rp = e["payload"]
        print(f"  · [{rp.get('mitre_technique','?')}] {rp.get('rule_desc','')[:72]}")

    if args.dry_run:
        print("\n[DRY RUN] Not submitted.")
        return

    cfg    = AegisPushConfig(url=args.aegis_url, token=args.token, enabled=True)
    result = _submit(events, cfg)
    print("\n" + "=" * 60)
    print(f"  ✅ object_id: {result.get('object_id','?')}")
    print(f"  status:      {result.get('status','?')}")
    print(f"  events:      {result.get('event_count','?')}")
    print(f"  Poll: GET {args.aegis_url}/api/pipeline/status/{result.get('object_id','?')}")
    print("=" * 60)


if __name__ == "__main__":
    _cli()

