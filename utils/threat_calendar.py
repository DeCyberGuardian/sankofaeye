"""
SankofaEye — Ghana Threat Calendar (Phase 5I)
AfriWealth Cyber Intelligence

Reads intel/threat_calendar.json and, for a given date (default: today),
returns the active threat context — which seasonal/election/monthly
high-risk windows are currently in effect and at what urgency.

Used to surface a time-sensitive banner on the dashboard, e.g.:
  "⚠️ Q2 financial close — BEC campaigns peak. Recommend increased email
   vigilance."

Returns a dict:
  {
    "active": bool,
    "periods": [ {label, urgency, context, threat_types, mitre, id}, ... ],
    "top": {...} | None,        # highest-urgency active period
    "urgency": "CRITICAL|HIGH|MEDIUM|INFO",
    "colour": "#RRGGBB",
    "summary": str,             # one-line banner text
    "checked_date": "YYYY-MM-DD",
  }
"""

import os
import json
from datetime import date, datetime

from utils.logger import SankofaLogger

log = SankofaLogger("threat_calendar")

CALENDAR_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "intel", "threat_calendar.json",
)

_URGENCY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
_URGENCY_COLOUR = {
    "CRITICAL": "#D32F2F",   # red
    "HIGH":     "#F57C00",   # orange
    "MEDIUM":   "#FBC02D",   # amber
    "INFO":     "#008080",   # teal
}


def _load_calendar() -> dict:
    if not os.path.exists(CALENDAR_PATH):
        log.warning(f"[ThreatCalendar] Not found at {CALENDAR_PATH}")
        return {}
    try:
        with open(CALENDAR_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        log.warning(f"[ThreatCalendar] Load error: {e}")
        return {}


def _in_md_range(today: date, start_md: str, end_md: str) -> bool:
    """
    True if today's month-day falls within a MM-DD..MM-DD window.
    Handles year-wrapping ranges (e.g. 11-20 .. 01-15).
    """
    try:
        sm, sd = map(int, start_md.split("-"))
        em, ed = map(int, end_md.split("-"))
    except Exception:
        return False
    tm, td = today.month, today.day
    start_val = sm * 100 + sd
    end_val   = em * 100 + ed
    today_val = tm * 100 + td
    if start_val <= end_val:
        return start_val <= today_val <= end_val
    # Wrap across year boundary (e.g. Nov 20 -> Jan 15)
    return today_val >= start_val or today_val <= end_val


def _in_monthly_range(today: date, start_spec: str, end_spec: str) -> bool:
    """
    Monthly window like 'monthly-25' .. 'monthly-03' (25th of a month
    through the 3rd of the next). Wraps month boundaries.
    """
    try:
        sd = int(start_spec.split("-")[1])
        ed = int(end_spec.split("-")[1])
    except Exception:
        return False
    d = today.day
    if sd <= ed:
        return sd <= d <= ed
    return d >= sd or d <= ed


def _in_date_range(today: date, start_iso: str, end_iso: str) -> bool:
    """Absolute YYYY-MM-DD range (used for elections)."""
    try:
        s = datetime.strptime(start_iso, "%Y-%m-%d").date()
        e = datetime.strptime(end_iso, "%Y-%m-%d").date()
    except Exception:
        return False
    return s <= today <= e


def _period_active(today: date, period: dict) -> bool:
    start = str(period.get("start", ""))
    end   = str(period.get("end", ""))
    if start.startswith("monthly-"):
        return _in_monthly_range(today, start, end)
    if len(start) == 10 and start[4] == "-":   # YYYY-MM-DD
        return _in_date_range(today, start, end)
    return _in_md_range(today, start, end)      # MM-DD


def get_active_threats(check_date: date = None) -> dict:
    """
    Return the active threat context for a date (default: today).
    """
    today = check_date or date.today()
    cal = _load_calendar()

    result = {
        "active": False,
        "periods": [],
        "top": None,
        "urgency": "INFO",
        "colour": _URGENCY_COLOUR["INFO"],
        "summary": "",
        "checked_date": today.isoformat(),
    }
    if not cal:
        return result

    all_periods = (cal.get("recurring_periods", []) +
                   cal.get("election_periods", []))

    active = []
    for p in all_periods:
        if _period_active(today, p):
            active.append({
                "id":           p.get("id"),
                "label":        p.get("label", ""),
                "urgency":      p.get("urgency", "INFO"),
                "context":      p.get("context", ""),
                "threat_types": p.get("threat_types", []),
                "mitre":        p.get("mitre", []),
            })

    if not active:
        result["summary"] = (
            "No elevated seasonal threat window is active today. "
            "Standard vigilance applies."
        )
        return result

    # Sort by urgency, highest first.
    active.sort(key=lambda x: _URGENCY_RANK.get(x["urgency"], 0), reverse=True)
    top = active[0]

    result["active"]  = True
    result["periods"] = active
    result["top"]     = top
    result["urgency"] = top["urgency"]
    result["colour"]  = _URGENCY_COLOUR.get(top["urgency"], _URGENCY_COLOUR["INFO"])
    result["summary"] = f"{top['label']} — {top['context']}"

    log.info(
        f"[ThreatCalendar] {today.isoformat()} — {len(active)} active "
        f"window(s); top: {top['label']} ({top['urgency']})"
    )
    return result