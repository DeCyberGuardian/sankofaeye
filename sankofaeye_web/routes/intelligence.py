"""
SankofaEye — Natural Language Query (Aegis-INT Bridge) — Phase 5H
AfriWealth Cyber Intelligence

The Enterprise feature: lets analysts ask plain-English questions about a
scan's findings and get answers framed in the West African threat context,
with MITRE technique references. Backed by the Claude API.

POST /intelligence/query
    JSON body: {"job_id": "<scan job id>", "question": "<user question>"}
    Returns:   {"answer": "<markdown text>"} | {"error": "..."}

Gated behind Professional / Enterprise plans. Free / Starter users get an
upgrade prompt instead of an answer.

Requires ANTHROPIC_API_KEY in the environment (.env).
"""

import os
import json

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user

intelligence_bp = Blueprint("intelligence", __name__)

# Plans permitted to use the NL query feature.
_ALLOWED_PLANS = {"professional", "enterprise"}

# Pinned model + token budget (per product spec).
_MODEL = "claude-sonnet-4-20250514"
_MAX_TOKENS = 1000

_SYSTEM_PROMPT = (
    "You are an expert CTI analyst at AfriWealth Cyber Intelligence "
    "specialising in Ghana and West Africa. Answer questions about the "
    "provided scan findings. Be specific, reference MITRE techniques by ID, "
    "and frame answers in the West African threat context. Be concise and "
    "actionable."
)

# Guard rails on the user question.
_MAX_QUESTION_LEN = 2000
# Cap the context we send so a huge scan JSON can't blow the token budget.
_MAX_CONTEXT_CHARS = 60000


def _load_scan_data(job_id: str):
    """Load the findings+scoring JSON for a job the current user owns."""
    ScanJob = current_app.config["SCAN_JOB_MODEL"]
    job = ScanJob.query.filter_by(id=job_id, user_id=current_user.id).first()
    if not job:
        return None, None, "Scan not found."
    if not job.json_path or not os.path.exists(job.json_path):
        return job, None, "Findings data not available for this scan."
    try:
        with open(job.json_path, "r") as f:
            data = json.load(f)
        return job, data, None
    except Exception:
        return job, None, "Could not read findings data."


@intelligence_bp.route("/intelligence/query", methods=["POST"])
@login_required
def query():
    # ── Plan gate ─────────────────────────────────────────────
    if current_user.plan not in _ALLOWED_PLANS:
        return jsonify({
            "error": "upgrade_required",
            "message": "Upgrade to Professional to query your findings with AI.",
        }), 403

    # ── Input validation ──────────────────────────────────────
    body = request.get_json(silent=True) or {}
    job_id   = (body.get("job_id") or "").strip()
    question = (body.get("question") or "").strip()

    if not job_id or not question:
        return jsonify({"error": "job_id and question are required."}), 400
    if len(question) > _MAX_QUESTION_LEN:
        return jsonify({"error": "Question is too long."}), 400

    # ── Load scan context (ownership enforced) ────────────────
    job, data, err = _load_scan_data(job_id)
    if err:
        return jsonify({"error": err}), 404

    findings = data.get("findings", {})
    scoring  = data.get("scoring", {})

    context_blob = json.dumps(
        {"findings": findings, "scoring": scoring}, separators=(",", ":")
    )
    if len(context_blob) > _MAX_CONTEXT_CHARS:
        context_blob = context_blob[:_MAX_CONTEXT_CHARS] + "...[truncated]"

    user_message = (
        f"Scan target: {findings.get('target', job.domain)}\n\n"
        f"Scan findings and scoring (JSON):\n{context_blob}\n\n"
        f"Question: {question}"
    )

    # ── Call Claude API ───────────────────────────────────────
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return jsonify({
            "error": "AI service is not configured. Set ANTHROPIC_API_KEY."
        }), 503

    try:
        import anthropic
    except ImportError:
        return jsonify({
            "error": "AI service unavailable (anthropic SDK not installed)."
        }), 503

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model=_MODEL,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        # Concatenate any text blocks in the response.
        answer = "".join(
            block.text for block in resp.content
            if getattr(block, "type", None) == "text"
        ).strip()
        if not answer:
            answer = "No answer was returned. Try rephrasing your question."
        return jsonify({"answer": answer})
    except Exception as e:
        current_app.logger.warning(f"[intelligence] Claude API error: {e}")
        return jsonify({
            "error": "The AI query failed. Please try again shortly."
        }), 502