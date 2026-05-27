"""Reports routes: list, download PDF, view JSON."""

import os
import json
from flask import Blueprint, render_template, send_file, abort, current_app
from flask_login import login_required, current_user

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
def list_reports():
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    jobs = (ScanJob.query
            .filter_by(user_id=current_user.id, status="complete")
            .order_by(ScanJob.created_at.desc())
            .all())
    return render_template("reports.html", jobs=jobs)


@reports_bp.route("/reports/<job_id>/download/<report_type>")
@login_required
def download_report(job_id, report_type):
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job     = ScanJob.query.filter_by(id=job_id, user_id=current_user.id).first_or_404()

    if report_type == "full" and job.pdf_path and os.path.exists(job.pdf_path):
        return send_file(job.pdf_path, as_attachment=True,
                         download_name=f"SankofahEye_{job.domain}_full_report.pdf")
    elif report_type == "exec" and job.exec_path and os.path.exists(job.exec_path):
        return send_file(job.exec_path, as_attachment=True,
                         download_name=f"SankofahEye_{job.domain}_executive_summary.pdf")
    elif report_type == "json" and job.json_path and os.path.exists(job.json_path):
        return send_file(job.json_path, as_attachment=True,
                         download_name=f"SankofahEye_{job.domain}_findings.json",
                         mimetype="application/json")
    abort(404)


@reports_bp.route("/reports/<job_id>/findings")
@login_required
def view_findings(job_id):
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job     = ScanJob.query.filter_by(id=job_id, user_id=current_user.id).first_or_404()

    findings_data = None
    if job.json_path and os.path.exists(job.json_path):
        with open(job.json_path, "r") as f:
            findings_data = json.load(f)

    return render_template("findings.html", job=job, data=findings_data)
