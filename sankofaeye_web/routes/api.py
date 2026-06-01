"""
SankofaEye — REST API + SIEM Export (Phase 5J)
AfriWealth Cyber Intelligence

Programmatic access to passive exposure scanning, for SOC automation and
SIEM ingestion. Authenticated with an X-API-Key header (per-user key,
auto-generated on the User model). Rate limited per plan.

Endpoints:
  POST /api/v1/scan                     submit a domain -> {job_id}
  GET  /api/v1/scan/<job_id>            poll status + full results JSON
  GET  /api/v1/export/splunk/<job_id>   findings as Splunk HEC events
  GET  /api/v1/export/elastic/<job_id>  findings as Elastic ECS documents
  GET  /api/v1/me                       plan, usage, API key

All responses are JSON. Errors: {"error": "...", "message": "..."} with an
appropriate HTTP status.
"""

import os
import time
import uuid
import json
import threading
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, jsonify, current_app

api_bp = Blueprint("api", __name__)

# ── Per-plan rate limits (requests per hour) ──────────────────────
_PLAN_RATE_LIMITS = {
    "free":         10,
    "starter":      60,
    "professional": 300,
    "enterprise":   3000,
}

# In-memory sliding-window rate-limit store: {api_key: [epoch, epoch, ...]}.
# Fine for a single-process deployment; swap for Redis when scaling out.
_RATE_BUCKETS = {}
_RATE_WINDOW = 3600  # seconds


# ── Auth + rate-limit decorator ───────────────────────────────────

def _rate_limited(api_key: str, limit: int) -> tuple:
    """Returns (is_limited, remaining, reset_epoch)."""
    now = time.time()
    bucket = [t for t in _RATE_BUCKETS.get(api_key, []) if now - t < _RATE_WINDOW]
    if len(bucket) >= limit:
        reset = int(bucket[0] + _RATE_WINDOW)
        _RATE_BUCKETS[api_key] = bucket
        return True, 0, reset
    bucket.append(now)
    _RATE_BUCKETS[api_key] = bucket
    return False, max(0, limit - len(bucket)), int(now + _RATE_WINDOW)


def require_api_key(fn):
    """Authenticate via X-API-Key, enforce per-plan rate limit, inject user."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        User = current_app.config["USER_MODEL"]
        key = request.headers.get("X-API-Key", "").strip()
        if not key:
            return jsonify({
                "error": "missing_api_key",
                "message": "Provide your key in the X-API-Key header.",
            }), 401
        user = User.query.filter_by(api_key=key).first()
        if not user:
            return jsonify({
                "error": "invalid_api_key",
                "message": "The provided API key is not valid.",
            }), 401

        limit = _PLAN_RATE_LIMITS.get(user.plan, _PLAN_RATE_LIMITS["free"])
        limited, remaining, reset = _rate_limited(key, limit)
        if limited:
            resp = jsonify({
                "error": "rate_limited",
                "message": f"Rate limit exceeded ({limit}/hour for {user.plan} plan).",
            })
            resp.headers["X-RateLimit-Limit"]     = str(limit)
            resp.headers["X-RateLimit-Remaining"] = "0"
            resp.headers["X-RateLimit-Reset"]     = str(reset)
            resp.headers["Retry-After"]           = str(max(1, reset - int(time.time())))
            return resp, 429

        # Stash for the view + attach limit headers on success.
        request.api_user = user
        request.api_rate = (limit, remaining, reset)
        return fn(*args, **kwargs)
    return wrapper


def _with_rate_headers(resp):
    """Attach X-RateLimit-* headers from request.api_rate to a response tuple/obj."""
    try:
        limit, remaining, reset = request.api_rate
        if isinstance(resp, tuple):
            body = resp[0]
            body.headers["X-RateLimit-Limit"]     = str(limit)
            body.headers["X-RateLimit-Remaining"] = str(remaining)
            body.headers["X-RateLimit-Reset"]     = str(reset)
        else:
            resp.headers["X-RateLimit-Limit"]     = str(limit)
            resp.headers["X-RateLimit-Remaining"] = str(remaining)
            resp.headers["X-RateLimit-Reset"]     = str(reset)
    except Exception:
        pass
    return resp


# ── Helpers ───────────────────────────────────────────────────────

def _load_results(job):
    """Load findings+scoring JSON for a completed job. Returns dict or None."""
    if not job.json_path or not os.path.exists(job.json_path):
        return None
    try:
        with open(job.json_path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _iter_finding_events(job, data):
    """
    Yield normalised finding events for SIEM export. Each event is a flat
    dict drawn from the scored findings list, enriched with scan metadata.
    """
    scoring  = (data or {}).get("scoring", {})
    findings = (data or {}).get("findings", {})
    target   = findings.get("target", job.domain)
    sector   = (findings.get("sector") or {}).get("key", "")
    for f in scoring.get("findings", []):
        mitre = f.get("mitre", {}) or {}
        yield {
            "job_id":       job.id,
            "target":       target,
            "sector":       sector,
            "finding":      f.get("finding", ""),
            "severity":     str(f.get("severity", "")).lower(),
            "detail":       f.get("detail", ""),
            "recommendation": f.get("recommendation", ""),
            "mitre_id":     mitre.get("id", ""),
            "mitre_name":   mitre.get("name", ""),
            "risk_score":   scoring.get("score"),
            "risk_rating":  scoring.get("rating"),
        }


# ── Endpoints ─────────────────────────────────────────────────────

@api_bp.route("/api/v1/me", methods=["GET"])
@require_api_key
def me():
    user = request.api_user
    limit, remaining, reset = request.api_rate
    return _with_rate_headers(jsonify({
        "email":         user.email,
        "plan":          user.plan,
        "api_key":       user.api_key,
        "scan_limit":    user.scan_limit,
        "scans_used":    user.scans_this_month(),
        "rate_limit":    {"limit": limit, "remaining": remaining, "reset": reset},
    }))


@api_bp.route("/api/v1/scan", methods=["POST"])
@require_api_key
def api_submit_scan():
    user    = request.api_user
    db      = current_app.config["DB"]
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    JOBS    = current_app.config["JOBS"]

    body   = request.get_json(silent=True) or {}
    domain = str(body.get("domain", "")).strip().lower()
    sector = str(body.get("sector", "")).strip().lower() or None

    if not domain:
        return jsonify({"error": "bad_request",
                        "message": "Field 'domain' is required."}), 400

    import re
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$", domain):
        return jsonify({"error": "bad_request",
                        "message": "Invalid domain format."}), 400

    # Validate sector if supplied.
    if sector:
        try:
            from utils.sector import SECTORS
            if sector not in SECTORS:
                sector = None
        except Exception:
            sector = None

    # Enforce monthly scan quota (-1 = unlimited).
    used  = user.scans_this_month()
    limit = user.scan_limit
    if limit != -1 and used >= limit:
        return jsonify({
            "error": "quota_exceeded",
            "message": f"Monthly scan limit reached ({used}/{limit}).",
        }), 402

    job_id     = str(uuid.uuid4())
    output_dir = os.path.join(current_app.config["SCAN_OUTPUT_DIR"], job_id)
    os.makedirs(output_dir, exist_ok=True)

    job = ScanJob(id=job_id, user_id=user.id, domain=domain, status="queued")
    db.session.add(job)
    db.session.commit()

    JOBS[job_id] = {
        "status": "queued", "progress": 0, "message": "Queued (API)...",
        "domain": domain, "pdf_path": None, "exec_path": None, "error": None,
        "started_at": datetime.utcnow().isoformat(),
    }

    # Reuse the same background worker the web UI uses.
    from routes.scan import _run_scan_worker
    t = threading.Thread(
        target=_run_scan_worker,
        args=(current_app._get_current_object(), job_id, domain,
              user.id, output_dir, sector),
        daemon=True,
    )
    t.start()

    resp = jsonify({
        "job_id": job_id,
        "domain": domain,
        "sector": sector or "auto",
        "status": "queued",
        "links": {
            "self":           f"/api/v1/scan/{job_id}",
            "export_splunk":  f"/api/v1/export/splunk/{job_id}",
            "export_elastic": f"/api/v1/export/elastic/{job_id}",
        },
    })
    return _with_rate_headers((resp, 202))


@api_bp.route("/api/v1/scan/<job_id>", methods=["GET"])
@require_api_key
def api_scan_status(job_id):
    user    = request.api_user
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    JOBS    = current_app.config["JOBS"]

    job = ScanJob.query.filter_by(id=job_id, user_id=user.id).first()
    if not job:
        return jsonify({"error": "not_found",
                        "message": "Scan not found."}), 404

    live = JOBS.get(job_id, {})
    payload = {
        "job_id":      job.id,
        "domain":      job.domain,
        "status":      job.status,
        "progress":    live.get("progress", 100 if job.status == "complete" else 0),
        "risk_score":  job.risk_score,
        "risk_rating": job.risk_rating,
        "created_at":  job.created_at.isoformat() if job.created_at else None,
    }
    if job.status == "complete":
        payload["results"] = _load_results(job)
    elif job.status == "failed":
        payload["error_message"] = job.error_msg
    return _with_rate_headers(jsonify(payload))


@api_bp.route("/api/v1/export/splunk/<job_id>", methods=["GET"])
@require_api_key
def api_export_splunk(job_id):
    """
    Splunk HEC-style events. Each finding becomes one event:
      {"time": epoch, "source": "sankofaeye", "sourcetype": "cti:exposure",
       "event": {finding fields}}
    Returned as a JSON array (newline-delimited also available via ?ndjson=1).
    """
    user    = request.api_user
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job = ScanJob.query.filter_by(id=job_id, user_id=user.id).first()
    if not job:
        return jsonify({"error": "not_found", "message": "Scan not found."}), 404
    if job.status != "complete":
        return jsonify({"error": "not_ready",
                        "message": f"Scan status is '{job.status}'."}), 409

    data = _load_results(job)
    epoch = int((job.completed_at or job.created_at or datetime.utcnow())
                .replace(tzinfo=timezone.utc).timestamp())
    events = [{
        "time":       epoch,
        "source":     "sankofaeye",
        "sourcetype": "cti:exposure",
        "host":       job.domain,
        "event":      ev,
    } for ev in _iter_finding_events(job, data)]

    if request.args.get("ndjson") == "1":
        body = "\n".join(json.dumps(e) for e in events)
        return current_app.response_class(body, mimetype="application/x-ndjson")
    return _with_rate_headers(jsonify({"events": events, "count": len(events)}))


@api_bp.route("/api/v1/export/elastic/<job_id>", methods=["GET"])
@require_api_key
def api_export_elastic(job_id):
    """
    Elastic ECS documents. Each finding becomes one ECS-shaped doc:
      {"@timestamp": iso, "event.kind": "alert",
       "event.category": ["intrusion_detection"],
       "threat.technique.id": mitre_id, "host.domain": target, ...}
    """
    user    = request.api_user
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job = ScanJob.query.filter_by(id=job_id, user_id=user.id).first()
    if not job:
        return jsonify({"error": "not_found", "message": "Scan not found."}), 404
    if job.status != "complete":
        return jsonify({"error": "not_ready",
                        "message": f"Scan status is '{job.status}'."}), 409

    data = _load_results(job)
    iso = (job.completed_at or job.created_at or datetime.utcnow()) \
        .replace(tzinfo=timezone.utc).isoformat()

    _ECS_SEV = {"critical": "critical", "high": "high",
                "medium": "medium", "low": "low"}
    docs = []
    for ev in _iter_finding_events(job, data):
        docs.append({
            "@timestamp":           iso,
            "event.kind":           "alert",
            "event.category":       ["intrusion_detection"],
            "event.severity":       _ECS_SEV.get(ev["severity"], "low"),
            "event.dataset":        "sankofaeye.exposure",
            "event.provider":       "AfriWealth Cyber Intelligence",
            "message":              ev["finding"],
            "rule.description":     ev["detail"],
            "host.domain":          ev["target"],
            "threat.technique.id":  ev["mitre_id"],
            "threat.technique.name": ev["mitre_name"],
            "vulnerability.severity": ev["severity"],
            "sankofaeye.recommendation": ev["recommendation"],
            "sankofaeye.risk_score": ev["risk_score"],
            "sankofaeye.sector":    ev["sector"],
            "labels": {"job_id": ev["job_id"]},
        })

    if request.args.get("ndjson") == "1":
        body = "\n".join(json.dumps(d) for d in docs)
        return current_app.response_class(body, mimetype="application/x-ndjson")
    return _with_rate_headers(jsonify({"documents": docs, "count": len(docs)}))


# ── Web UI: API settings page (login-required, not key-auth) ──────

from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user


@api_bp.route("/settings/api", methods=["GET"])
@login_required
def api_settings():
    """Show the user's API key, usage, and example calls."""
    db = current_app.config["DB"]
    # Backfill a key for accounts created before the api_key column existed.
    if not current_user.api_key:
        current_user.api_key = uuid.uuid4().hex
        db.session.commit()
    limit = _PLAN_RATE_LIMITS.get(current_user.plan, _PLAN_RATE_LIMITS["free"])
    return render_template("api_settings.html", rate_limit=limit)


@api_bp.route("/settings/api/regenerate", methods=["POST"])
@login_required
def api_regenerate_key():
    """Rotate the user's API key. The old key stops working immediately."""
    db = current_app.config["DB"]
    current_user.api_key = uuid.uuid4().hex
    db.session.commit()
    flash("API key regenerated. Update any integrations using the old key.", "success")
    return redirect(url_for("api.api_settings"))