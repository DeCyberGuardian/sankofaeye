"""
SankofahEye — Scheduled Scan Scheduler
AfriWealth Cyber Intelligence

Runs recurring passive scans per user domain on a schedule:
  - Starter plan:      monthly
  - Professional plan: weekly

On each scheduled scan:
  1. Runs full SankofahEye pipeline
  2. Compares findings against previous scan (delta)
  3. If new findings detected → sends email report
  4. Always saves full PDF to user's account

Run this as a background process alongside the Flask app:
    python scheduler/scan_scheduler.py

Or add to crontab (run every hour, scheduler handles timing):
    0 * * * * /path/to/venv/bin/python /path/to/sankofaeye/scheduler/scan_scheduler.py
"""

import os
import sys
import json
import time
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# ── Path setup ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "sankofaeye_web"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(BASE_DIR, "logs", "scheduler.log")),
    ]
)
log = logging.getLogger("scheduler")


# ── Schedule intervals ─────────────────────────────────────────────────────────
PLAN_INTERVALS = {
    "starter":      30,   # days between scans
    "professional":  7,   # days between scans
    "free":         None, # no scheduled scans (manual only)
}


# ── Delta report builder ───────────────────────────────────────────────────────

def build_delta(current_scoring: dict, previous_scoring: dict) -> dict:
    """
    Compare two scoring dicts and return a delta report.
    
    Returns:
        dict with:
            new_findings:      findings in current not in previous
            resolved_findings: findings in previous not in current
            score_change:      int (positive = worse, negative = better)
            has_changes:       bool
    """
    current_findings  = {f["finding"] for f in current_scoring.get("findings", [])}
    previous_findings = {f["finding"] for f in previous_scoring.get("findings", [])}

    new_findings = [
        f for f in current_scoring.get("findings", [])
        if f["finding"] not in previous_findings
    ]
    resolved_findings = [
        f for f in previous_scoring.get("findings", [])
        if f["finding"] not in current_findings
    ]

    score_change = current_scoring.get("score", 0) - previous_scoring.get("score", 0)

    return {
        "new_findings":      new_findings,
        "resolved_findings": resolved_findings,
        "score_change":      score_change,
        "current_score":     current_scoring.get("score", 0),
        "previous_score":    previous_scoring.get("score", 0),
        "current_rating":    current_scoring.get("rating", ""),
        "previous_rating":   previous_scoring.get("rating", ""),
        "has_changes":       bool(new_findings or resolved_findings),
        "new_critical_high": [f for f in new_findings
                               if f.get("severity") in ("critical", "high")],
    }


# ── Email delivery ─────────────────────────────────────────────────────────────

def send_report_email(
    recipient_email: str,
    domain: str,
    scoring: dict,
    delta: dict,
    pdf_path: str = None,
    exec_path: str = None,
) -> bool:
    """
    Send scan report email with delta summary and PDF attachments.
    
    Required .env variables:
        SMTP_HOST       e.g. smtp.gmail.com
        SMTP_PORT       e.g. 587
        SMTP_USER       e.g. reports@afriwealthci.com
        SMTP_PASSWORD   app password
        SMTP_FROM       AfriWealth Cyber Intelligence <reports@afriwealthci.com>
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not all([smtp_host, smtp_user, smtp_pass]):
        log.warning(f"[Scheduler] SMTP not configured — skipping email to {recipient_email}")
        return False

    score  = scoring.get("score", 0)
    rating = scoring.get("rating", "").upper()
    new_ct = len(delta.get("new_findings", []))
    res_ct = len(delta.get("resolved_findings", []))
    sc     = delta.get("score_change", 0)
    sc_str = f"+{sc}" if sc > 0 else str(sc)

    # ── Build email body ───────────────────────────────────────
    subject = (
        f"[SankofahEye] {domain} — Scheduled Scan Complete "
        f"({score}/100 {rating})"
        + (f" — {new_ct} NEW finding(s)" if new_ct else "")
    )

    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;color:#212121;max-width:600px;margin:0 auto;">
    
    <div style="background:#005F5F;padding:20px;border-bottom:3px solid #FFD700;">
      <h1 style="color:white;margin:0;font-size:20px;">SankofahEye</h1>
      <p style="color:#FFD700;margin:4px 0 0;font-size:12px;">
        AfriWealth Cyber Intelligence — Scheduled Scan Report
      </p>
    </div>
    
    <div style="padding:24px 20px;">
      <h2 style="color:#008080;margin:0 0 16px;">
        Passive Exposure Assessment: <strong>{domain}</strong>
      </h2>
      <p style="color:#757575;font-size:13px;">
        {datetime.now().strftime('%d %B %Y, %H:%M UTC')}
      </p>
      
      <div style="background:#F5F5F5;border-radius:6px;padding:16px;margin:16px 0;
                  display:flex;gap:20px;flex-wrap:wrap;">
        <div style="text-align:center;min-width:80px;">
          <div style="font-size:36px;font-weight:800;
                      color:{'#D32F2F' if rating=='CRITICAL' else '#F57C00' if rating=='HIGH' else '#FBC02D' if rating=='MEDIUM' else '#388E3C'};">
            {score}
          </div>
          <div style="font-size:11px;color:#757575;">/100 {rating}</div>
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:6px;">
            Score change from last scan: 
            <strong style="color:{'#D32F2F' if sc > 0 else '#388E3C' if sc < 0 else '#757575'};">
              {sc_str} points
            </strong>
          </div>
          <div style="font-size:13px;">
            New findings: <strong style="color:{'#D32F2F' if new_ct > 0 else '#388E3C'};">
              {new_ct}
            </strong>
          </div>
          <div style="font-size:13px;">
            Resolved since last scan: <strong style="color:#388E3C;">{res_ct}</strong>
          </div>
        </div>
      </div>
      
      {"" if not delta.get("new_critical_high") else f'''
      <div style="background:#FFEBEE;border-left:4px solid #D32F2F;padding:12px 16px;
                  border-radius:4px;margin:16px 0;">
        <strong style="color:#B71C1C;">New Critical/High Findings Requiring Attention:</strong>
        <ul style="margin:8px 0 0;padding-left:20px;font-size:13px;">
          {"".join(f'<li>{f["finding"]}</li>' for f in delta["new_critical_high"])}
        </ul>
      </div>
      '''}
      
      <p style="font-size:13px;color:#757575;">
        Full PDF report and executive summary are attached.
        Log in to your dashboard to view all findings.
      </p>
      
      <a href="{os.getenv('APP_BASE_URL', 'http://localhost:8080')}/dashboard"
         style="display:inline-block;background:#008080;color:white;
                padding:10px 20px;border-radius:4px;text-decoration:none;
                font-size:13px;font-weight:600;">
        View Dashboard
      </a>
    </div>
    
    <div style="background:#F5F5F5;padding:14px 20px;font-size:11px;color:#757575;
                border-top:1px solid #E0E0E0;">
      AfriWealth Cyber Intelligence | afriwealthci.com<br>
      Passive reconnaissance only — no active exploitation performed.
    </div>
    
    </body></html>
    """

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"]    = smtp_from
    msg["To"]      = recipient_email

    msg.attach(MIMEText(html_body, "html"))

    # Attach PDFs
    for path, name in [
        (pdf_path,  f"SankofahEye_{domain}_full_report.pdf"),
        (exec_path, f"SankofahEye_{domain}_executive_summary.pdf"),
    ]:
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                part = MIMEBase("application", "pdf")
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition",
                                f'attachment; filename="{name}"')
                msg.attach(part)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [recipient_email], msg.as_string())
        log.info(f"[Scheduler] Email sent to {recipient_email} for {domain}")
        return True
    except Exception as e:
        log.error(f"[Scheduler] Email failed for {recipient_email}: {e}")
        return False


# ── Core scheduler ─────────────────────────────────────────────────────────────

def run_scheduled_scan(user_email: str, user_id: int, domain: str,
                       plan: str, output_dir: str, config: dict) -> dict:
    """
    Run a scheduled scan for one user+domain combination.
    Returns dict with scan results summary.
    """
    log.info(f"[Scheduler] Starting scheduled scan: {domain} (user {user_id}, {plan} plan)")

    try:
        from sankofaeye import run_scan
        pdf_path = run_scan(domain, config, output_dir)

        # Find generated files
        exec_path = json_path = None
        for fname in sorted(os.listdir(output_dir), reverse=True):
            fpath = os.path.join(output_dir, fname)
            if fname.startswith(f"SankofahEye_{domain}_") and fname.endswith(".json") and not json_path:
                json_path = fpath
            if "executive_summary" in fname and fname.endswith(".pdf") and not exec_path:
                exec_path = fpath

        # Load current scoring
        current_scoring = {}
        if json_path and os.path.exists(json_path):
            with open(json_path, "r") as f:
                current_scoring = json.load(f).get("scoring", {})

        return {
            "success":      True,
            "pdf_path":     pdf_path,
            "exec_path":    exec_path,
            "json_path":    json_path,
            "scoring":      current_scoring,
        }

    except Exception as e:
        log.error(f"[Scheduler] Scan failed for {domain}: {e}")
        return {"success": False, "error": str(e)}


def get_previous_scoring(user_id: int, domain: str, db_session) -> dict:
    """Load scoring from the most recent previous completed scan for this user+domain."""
    try:
        from app import ScanJob
        prev = (ScanJob.query
                .filter_by(user_id=user_id, domain=domain, status="complete")
                .order_by(ScanJob.created_at.desc())
                .offset(1)  # skip the most recent (current)
                .first())

        if prev and prev.json_path and os.path.exists(prev.json_path):
            with open(prev.json_path, "r") as f:
                return json.load(f).get("scoring", {})
    except Exception:
        pass
    return {}


def run_all_scheduled(app_instance):
    """
    Check all users with scheduled plans and run overdue scans.
    Called by the main loop.
    """
    with app_instance.app_context():
        from app import db, User, ScanJob
        import yaml

        config_path = os.path.join(BASE_DIR, "config.yaml")
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
        else:
            log.warning("[Scheduler] config.yaml not found — using defaults")
            config = {"brand": {"tool": "SankofahEye", "version": "1.0.0",
                                "name": "AfriWealth Cyber Intelligence",
                                "analyst": "DeCyberGuardian",
                                "website": "https://afriwealthci.com"},
                      "modules": {}, "timeouts": {},
                      "output": {"pdf_report": True, "json_dump": True,
                                 "log_directory": "logs", "log_level": "INFO"},
                      "risk_weights": {}}

        users = User.query.filter(User.plan.in_(["starter", "professional"])).all()
        log.info(f"[Scheduler] Checking {len(users)} user(s) on paid plans")

        for user in users:
            interval_days = PLAN_INTERVALS.get(user.plan)
            if not interval_days:
                continue

            # Get all domains this user has scanned
            domains = (db.session.query(ScanJob.domain)
                       .filter_by(user_id=user.id)
                       .distinct()
                       .all())

            for (domain,) in domains:
                # Find last scheduled scan for this domain
                last_scan = (ScanJob.query
                             .filter_by(user_id=user.id, domain=domain,
                                        status="complete")
                             .order_by(ScanJob.created_at.desc())
                             .first())

                if last_scan:
                    next_due = last_scan.created_at + timedelta(days=interval_days)
                    if datetime.utcnow() < next_due:
                        log.info(f"[Scheduler] {domain} not due yet (next: {next_due.date()})")
                        continue

                log.info(f"[Scheduler] Running scheduled scan: {domain} ({user.plan})")

                output_dir = os.path.join(BASE_DIR, "output",
                                          f"scheduled_{user.id}_{domain}")
                os.makedirs(output_dir, exist_ok=True)

                result = run_scheduled_scan(
                    user.email, user.id, domain, user.plan, output_dir, config
                )

                if result["success"]:
                    # Save to DB
                    import uuid
                    job = ScanJob(
                        id=str(uuid.uuid4()),
                        user_id=user.id,
                        domain=domain,
                        status="complete",
                        risk_score=result["scoring"].get("score"),
                        risk_rating=result["scoring"].get("rating"),
                        pdf_path=result["pdf_path"],
                        exec_path=result["exec_path"],
                        json_path=result["json_path"],
                        completed_at=datetime.utcnow(),
                    )
                    db.session.add(job)
                    db.session.commit()

                    # Build delta
                    prev_scoring = get_previous_scoring(user.id, domain, db.session)
                    delta = build_delta(result["scoring"], prev_scoring)

                    # Send email if new findings or first scan
                    if delta["has_changes"] or not prev_scoring:
                        send_report_email(
                            recipient_email=user.email,
                            domain=domain,
                            scoring=result["scoring"],
                            delta=delta,
                            pdf_path=result["pdf_path"],
                            exec_path=result["exec_path"],
                        )
                else:
                    log.error(f"[Scheduler] Failed: {domain} — {result.get('error')}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("[Scheduler] SankofahEye scan scheduler starting...")

    # Import Flask app for DB context
    sys.path.insert(0, os.path.join(BASE_DIR, "sankofaeye_web"))
    from app import app

    # Run once immediately, then every hour
    while True:
        try:
            run_all_scheduled(app)
        except Exception as e:
            log.error(f"[Scheduler] Unexpected error: {e}")

        log.info("[Scheduler] Sleeping 1 hour until next check...")
        time.sleep(3600)
