"""
Scan routes: dashboard, submit scan, poll status.
Background scans run in a thread — progress polled via /scan/status/<job_id>.
"""

import os
import sys
import json
import uuid
import threading
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, \
                  url_for, flash, jsonify, current_app
from flask_login import login_required, current_user

scan_bp = Blueprint("scan", __name__)


# ── Background scan worker ─────────────────────────────────────────────────────

def _run_scan_worker(app, job_id: str, domain: str, user_id: int, output_dir: str):
    """
    Runs in a background thread. Executes full SankofahEye scan pipeline,
    updates job status, saves results to DB.
    """
    with app.app_context():
        JOBS    = app.config["JOBS"]
        db      = app.config["DB"]
        ScanJob = app.config["SCAN_JOB_MODEL"]

        def _progress(pct: int, msg: str):
            JOBS[job_id]["progress"] = pct
            JOBS[job_id]["message"]  = msg

        try:
            JOBS[job_id]["status"]   = "running"
            JOBS[job_id]["progress"] = 0
            JOBS[job_id]["message"]  = "Initialising scan..."

            # ── Load config ───────────────────────────────────
            base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(os.path.dirname(base_dir), "config.yaml")

            if not os.path.exists(config_path):
                # Fallback minimal config
                config = {
                    "brand": {
                        "tool": "SankofahEye", "version": "1.0.0",
                        "name": "AfriWealth Cyber Intelligence",
                        "analyst": "DeCyberGuardian",
                        "website": "https://afriwealthci.com",
                    },
                    "modules": {
                        "subfinder": True, "theharvester": True, "shodan": True,
                        "hibp": True, "virustotal": True, "urlscan": True,
                        "darkweb": True, "hudsonrock": True, "dns": True, "ssl": True,
                    },
                    "timeouts": {
                        "subfinder": 60, "theharvester": 90, "shodan": 30,
                        "hibp": 20, "virustotal": 30, "darkweb": 45,
                        "hudsonrock": 30, "dns": 30, "ssl": 45,
                    },
                    "output": {
                        "pdf_report": True, "json_dump": True,
                        "log_directory": "/tmp", "log_level": "INFO",
                    },
                    "risk_weights": {},
                }
            else:
                import yaml
                with open(config_path, "r") as f:
                    config = yaml.safe_load(f)

            # ── Import scan pipeline ──────────────────────────
            sys.path.insert(0, os.path.dirname(base_dir))
            from sankofaeye import run_scan

            _progress(5, "Running passive reconnaissance modules...")

            # Monkey-patch logger to feed progress back
            # The scan itself logs progress — we do rough % mapping
            def _scan_with_progress():
                _progress(10, "Enumerating subdomains...")
                result = run_scan(domain, config, output_dir)
                return result

            pdf_path = _scan_with_progress()
            _progress(90, "Generating reports...")

            # Find the generated files
            exec_path = None
            json_path = None

            if os.path.exists(output_dir):
                for fname in sorted(os.listdir(output_dir), reverse=True):
                    fpath = os.path.join(output_dir, fname)
                    if fname.startswith(f"SankofahEye_{domain}_") and fname.endswith(".json") and json_path is None:
                        json_path = fpath
                    if fname.startswith(f"SankofahEye_{domain}_executive_") and fname.endswith(".pdf") and exec_path is None:
                        exec_path = fpath

            # Read score from JSON
            risk_score  = None
            risk_rating = None
            if json_path and os.path.exists(json_path):
                with open(json_path, "r") as jf:
                    scan_data   = json.load(jf)
                    scoring     = scan_data.get("scoring", {})
                    risk_score  = scoring.get("score")
                    risk_rating = scoring.get("rating")

            # Update DB record
            job = ScanJob.query.get(job_id)
            if job:
                job.status       = "complete"
                job.risk_score   = risk_score
                job.risk_rating  = risk_rating
                job.pdf_path     = pdf_path
                job.exec_path    = exec_path
                job.json_path    = json_path
                job.completed_at = datetime.utcnow()
                db.session.commit()

            JOBS[job_id]["status"]    = "complete"
            JOBS[job_id]["progress"]  = 100
            JOBS[job_id]["message"]   = "Scan complete."
            JOBS[job_id]["pdf_path"]  = pdf_path
            JOBS[job_id]["exec_path"] = exec_path
            JOBS[job_id]["score"]     = risk_score
            JOBS[job_id]["rating"]    = risk_rating

        except Exception as e:
            JOBS[job_id]["status"]  = "failed"
            JOBS[job_id]["message"] = str(e)
            JOBS[job_id]["error"]   = str(e)

            job = ScanJob.query.get(job_id)
            if job:
                job.status    = "failed"
                job.error_msg = str(e)
                db.session.commit()


# ── Routes ─────────────────────────────────────────────────────────────────────

@scan_bp.route("/dashboard")
@login_required
def dashboard():
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    recent  = (ScanJob.query
               .filter_by(user_id=current_user.id)
               .order_by(ScanJob.created_at.desc())
               .limit(10)
               .all())
    scans_used  = current_user.scans_this_month()
    scans_limit = current_user.scan_limit

    # Load compliance + WA intel from the most recent completed scan
    compliance = {}
    wa_intel   = {}
    momo       = {}
    last_scan  = (ScanJob.query
                  .filter_by(user_id=current_user.id, status="complete")
                  .order_by(ScanJob.created_at.desc())
                  .first())
    if last_scan and last_scan.json_path:
        try:
            import json, os
            if os.path.exists(last_scan.json_path):
                with open(last_scan.json_path, "r") as f:
                    data = json.load(f)
                findings   = data.get("findings", {})
                compliance = findings.get("compliance", {})
                wa_intel   = findings.get("wa_intel", {})
                momo       = findings.get("momo_exposure", {})
        except Exception:
            pass

    return render_template("dashboard.html",
                           recent=recent,
                           scans_used=scans_used,
                           scans_limit=scans_limit,
                           compliance=compliance,
                           wa_intel=wa_intel,
                           momo=momo)


@scan_bp.route("/scan", methods=["POST"])
@login_required
def submit_scan():
    db      = current_app.config["DB"]
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    JOBS    = current_app.config["JOBS"]

    domain = request.form.get("domain", "").strip().lower()
    if not domain:
        flash("Please enter a domain.", "error")
        return redirect(url_for("scan.dashboard"))

    # Basic validation
    import re
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$", domain):
        flash("Invalid domain format.", "error")
        return redirect(url_for("scan.dashboard"))

    # Enforce monthly scan limit (-1 = unlimited)
    used  = current_user.scans_this_month()
    limit = current_user.scan_limit
    if limit != -1 and used >= limit:
        flash(
            f"Monthly scan limit reached ({used}/{limit}). "
            "Upgrade your plan for more scans.",
            "warning"
        )
        return redirect(url_for("scan.dashboard"))

    # Create job
    job_id     = str(uuid.uuid4())
    output_dir = os.path.join(current_app.config["SCAN_OUTPUT_DIR"], job_id)
    os.makedirs(output_dir, exist_ok=True)

    job = ScanJob(id=job_id, user_id=current_user.id, domain=domain, status="queued")
    db.session.add(job)
    db.session.commit()

    JOBS[job_id] = {
        "status":   "queued",
        "progress": 0,
        "message":  "Queued...",
        "domain":   domain,
        "pdf_path": None,
        "exec_path": None,
        "error":    None,
        "started_at": datetime.utcnow().isoformat(),
    }

    # Launch background thread
    t = threading.Thread(
        target=_run_scan_worker,
        args=(current_app._get_current_object(), job_id, domain,
              current_user.id, output_dir),
        daemon=True,
    )
    t.start()

    return redirect(url_for("scan.scan_progress", job_id=job_id))


@scan_bp.route("/scan/<job_id>")
@login_required
def scan_progress(job_id):
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job     = ScanJob.query.filter_by(id=job_id, user_id=current_user.id).first_or_404()
    return render_template("scan_progress.html", job=job)


@scan_bp.route("/scan/status/<job_id>")
@login_required
def scan_status(job_id):
    """JSON polling endpoint — called every 3s by the progress page."""
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    JOBS    = current_app.config["JOBS"]

    # Check in-memory first (live job)
    if job_id in JOBS:
        j = JOBS[job_id]
        return jsonify({
            "status":   j.get("status"),
            "progress": j.get("progress", 0),
            "message":  j.get("message", ""),
            "score":    j.get("score"),
            "rating":   j.get("rating"),
            "error":    j.get("error"),
        })

    # Fall back to DB (completed job from a previous session)
    job = ScanJob.query.filter_by(id=job_id, user_id=current_user.id).first_or_404()
    return jsonify({
        "status":   job.status,
        "progress": 100 if job.status == "complete" else 0,
        "message":  "Complete." if job.status == "complete" else job.error_msg or "",
        "score":    job.risk_score,
        "rating":   job.risk_rating,
        "error":    job.error_msg,
    })