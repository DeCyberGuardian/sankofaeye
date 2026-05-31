"""
SankofahEye — Remediation Tracker
AfriWealth Cyber Intelligence

Tracks the status of security findings across scans.
Clients mark findings as "In Progress" or "Resolved" via the
web interface. The next scheduled scan automatically verifies
whether the fix actually worked.

This turns SankofahEye from a one-time report into a
security programme management tool. Clients don't cancel
tools that track their progress.

Finding states:
  OPEN       → newly detected, no action taken
  IN_PROGRESS → assigned, fix in progress
  RESOLVED   → marked fixed by user
  VERIFIED   → confirmed fixed by subsequent scan (auto)
  REOPENED   → was resolved/verified but re-appeared in new scan
  ACCEPTED   → risk accepted, will not fix (requires reason)

Stored in SQLite via Flask-SQLAlchemy (same DB as web app).
"""

import os
import sys
import json
from datetime import datetime
from utils.logger import SankofahLogger

log = SankofahLogger("remediation_tracker")


# ── Fingerprint builder ────────────────────────────────────────────────────────

def finding_fingerprint(finding: dict) -> str:
    """
    Create a stable fingerprint for a finding so we can track it
    across scans even if the detail text changes slightly.
    Uses MITRE technique + severity + finding category (first 6 words).
    """
    mitre    = finding.get("mitre", {}).get("id", "")
    severity = finding.get("severity", "")
    title    = " ".join(finding.get("finding", "").lower().split()[:6])
    return f"{mitre}::{severity}::{title}"


# ── Tracker class ──────────────────────────────────────────────────────────────

class RemediationTracker:
    """
    Manages finding lifecycle across scans for a given domain + user.
    Can operate standalone (JSON file) or via Flask app DB context.
    """

    STATES = ["open", "in_progress", "resolved", "verified", "reopened", "accepted"]

    def __init__(self, domain: str, user_id: int = None, storage_path: str = None):
        self.domain       = domain
        self.user_id      = user_id
        self.storage_path = storage_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "output", f"remediation_{domain.replace('.','_')}.json"
        )
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "domain":    self.domain,
            "user_id":   self.user_id,
            "findings":  {},
            "created":   datetime.utcnow().isoformat(),
            "updated":   datetime.utcnow().isoformat(),
        }

    def _save(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        self._data["updated"] = datetime.utcnow().isoformat()
        with open(self.storage_path, "w") as f:
            json.dump(self._data, f, indent=2)

    # ── Ingest new scan findings ───────────────────────────────────────────────

    def ingest_scan(self, findings_list: list, scan_date: str = None) -> dict:
        """
        Process findings from a new scan.
        - New findings → OPEN
        - Previously RESOLVED/VERIFIED findings that reappear → REOPENED
        - Previously RESOLVED/VERIFIED findings that don't reappear → keep VERIFIED

        Returns:
            dict with new_count, reopened_count, verified_count
        """
        scan_date    = scan_date or datetime.utcnow().isoformat()
        new_fps      = {finding_fingerprint(f): f for f in findings_list}
        new_count    = 0
        reopened     = 0
        verified     = 0

        # Check for resolved findings that were fixed
        for fp, item in self._data["findings"].items():
            if item["status"] in ("resolved", "in_progress") and fp not in new_fps:
                item["status"]      = "verified"
                item["verified_at"] = scan_date
                item["verified_by"] = "scan"
                verified += 1
                log.info(f"[Tracker] ✅ VERIFIED fixed: {item['title'][:60]}")

        # Process findings from new scan
        for fp, finding in new_fps.items():
            if fp not in self._data["findings"]:
                # Brand new finding
                self._data["findings"][fp] = {
                    "fingerprint":    fp,
                    "title":          finding.get("finding", ""),
                    "severity":       finding.get("severity", ""),
                    "mitre":          finding.get("mitre", {}).get("id", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "status":         "open",
                    "first_seen":     scan_date,
                    "last_seen":      scan_date,
                    "history":        [{"date": scan_date, "event": "detected"}],
                    "assignee":       None,
                    "due_date":       None,
                    "notes":          "",
                    "accepted_reason": None,
                }
                new_count += 1
            else:
                item = self._data["findings"][fp]
                item["last_seen"] = scan_date

                # Reopened?
                if item["status"] in ("resolved", "verified"):
                    item["status"] = "reopened"
                    item["history"].append({
                        "date":  scan_date,
                        "event": "reopened — finding reappeared after being marked resolved"
                    })
                    reopened += 1
                    log.warning(f"[Tracker] ⚠️ REOPENED: {item['title'][:60]}")
                else:
                    item["history"].append({"date": scan_date, "event": "still open"})

        self._save()

        summary = {
            "new_count":      new_count,
            "reopened_count": reopened,
            "verified_count": verified,
            "total_open":     sum(1 for i in self._data["findings"].values()
                                  if i["status"] in ("open", "in_progress", "reopened")),
        }
        log.info(f"[Tracker] Scan ingested: +{new_count} new | {reopened} reopened | {verified} verified")
        return summary

    # ── Status updates ─────────────────────────────────────────────────────────

    def update_status(self, fingerprint: str, status: str,
                      assignee: str = None, due_date: str = None,
                      notes: str = None, accepted_reason: str = None) -> bool:
        """Update a finding's remediation status."""
        if fingerprint not in self._data["findings"]:
            return False
        if status not in self.STATES:
            return False

        item           = self._data["findings"][fingerprint]
        old_status     = item["status"]
        item["status"] = status
        item["history"].append({
            "date":  datetime.utcnow().isoformat(),
            "event": f"status changed: {old_status} → {status}",
            "by":    assignee or "user",
        })

        if assignee:    item["assignee"] = assignee
        if due_date:    item["due_date"] = due_date
        if notes:       item["notes"]    = notes
        if accepted_reason: item["accepted_reason"] = accepted_reason

        self._save()
        log.info(f"[Tracker] {fingerprint[:40]} → {status}")
        return True

    # ── Summary views ──────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        """Return a summary of finding statuses."""
        counts = {s: 0 for s in self.STATES}
        overdue = []
        now = datetime.utcnow().isoformat()

        for fp, item in self._data["findings"].items():
            counts[item["status"]] += 1
            if (item.get("due_date") and item["due_date"] < now
                    and item["status"] not in ("resolved", "verified", "accepted")):
                overdue.append(item)

        total_open = counts["open"] + counts["in_progress"] + counts["reopened"]

        # Compute fix rate
        total_ever  = len(self._data["findings"])
        total_fixed = counts["verified"] + counts["resolved"]
        fix_rate    = round((total_fixed / total_ever * 100)) if total_ever else 0

        return {
            "domain":     self.domain,
            "counts":     counts,
            "total_open": total_open,
            "total_fixed": total_fixed,
            "fix_rate":   fix_rate,
            "overdue":    len(overdue),
            "overdue_items": overdue[:5],
            "last_updated": self._data.get("updated"),
        }

    def get_open_findings(self, severity_filter: str = None) -> list:
        """Return all open/in-progress/reopened findings."""
        results = []
        for fp, item in self._data["findings"].items():
            if item["status"] not in ("open", "in_progress", "reopened"):
                continue
            if severity_filter and item["severity"] != severity_filter:
                continue
            results.append({**item, "fingerprint": fp})

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: sev_order.get(x["severity"], 99))
        return results

    def get_all_findings(self) -> list:
        """Return all findings with current status."""
        return [
            {**item, "fingerprint": fp}
            for fp, item in self._data["findings"].items()
        ]