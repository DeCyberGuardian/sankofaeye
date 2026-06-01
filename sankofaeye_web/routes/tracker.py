"""
SankofaEye Web — Remediation Tracker Routes
Handles finding status updates, tracker view, and alert settings.
"""

import os
import sys
import json
from flask import Blueprint, render_template, request, redirect, \
                  url_for, flash, jsonify, current_app
from flask_login import login_required, current_user

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE_DIR)

tracker_bp = Blueprint("tracker", __name__, url_prefix="/tracker")


def _get_tracker(domain: str, job_id: str):
    """Load remediation tracker for a domain."""
    from utils.remediation_tracker import RemediationTracker
    output_dir   = current_app.config.get("SCAN_OUTPUT_DIR", os.path.join(BASE_DIR, "output"))
    storage_path = os.path.join(output_dir, job_id,
                                f"remediation_{domain.replace('.','_')}.json")
    return RemediationTracker(domain, current_user.id, storage_path)


@tracker_bp.route("/<job_id>")
@login_required
def view(job_id):
    """Remediation tracker view for a scan job."""
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job     = ScanJob.query.filter_by(id=job_id, user_id=current_user.id).first_or_404()

    tracker  = _get_tracker(job.domain, job_id)
    summary  = tracker.get_summary()
    findings = tracker.get_all_findings()

    return render_template("tracker.html",
                           job=job,
                           summary=summary,
                           findings=findings)


@tracker_bp.route("/<job_id>/update", methods=["POST"])
@login_required
def update_status(job_id):
    """Update a finding's remediation status via AJAX."""
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job     = ScanJob.query.filter_by(id=job_id, user_id=current_user.id).first_or_404()

    data        = request.get_json()
    fingerprint = data.get("fingerprint")
    status      = data.get("status")
    notes       = data.get("notes", "")
    due_date    = data.get("due_date")
    reason      = data.get("accepted_reason", "")

    if not fingerprint or not status:
        return jsonify({"error": "Missing fingerprint or status"}), 400

    tracker = _get_tracker(job.domain, job_id)
    success = tracker.update_status(
        fingerprint, status,
        assignee=current_user.email,
        due_date=due_date,
        notes=notes,
        accepted_reason=reason,
    )

    if success:
        return jsonify({"ok": True, "summary": tracker.get_summary()})
    return jsonify({"error": "Finding not found"}), 404


@tracker_bp.route("/alerts", methods=["GET", "POST"])
@login_required
def alert_settings():
    """Alert configuration page."""
    db   = current_app.config["DB"]
    User = current_app.config["USER_MODEL"]

    if request.method == "POST":
        user = User.query.get(current_user.id)
        user.alert_email    = request.form.get("alert_email", "").strip()
        user.alert_phone    = request.form.get("alert_phone", "").strip()
        user.alert_channels = ",".join(request.form.getlist("channels"))
        user.alert_webhook  = request.form.get("webhook_url", "").strip()
        db.session.commit()
        flash("Alert settings saved.", "success")
        return redirect(url_for("tracker.alert_settings"))

    return render_template("alert_settings.html")
