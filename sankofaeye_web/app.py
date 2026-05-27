"""
SankofahEye Web — Flask Application
AfriWealth Cyber Intelligence

Free tier:  1 scan/month, watermarked report
Starter:    $49/month — 5 domains, monthly scans
Professional: $149/month — 20 domains, weekly scans + executive one-pager
"""

import os
import sys
import json
import uuid
import threading
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, \
                  flash, send_file, jsonify, session
from flask_login import LoginManager, login_user, logout_user, \
                        login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ── Path setup — allow imports from the parent sankofaeye package ──────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

app = Flask(__name__)
app.config["SECRET_KEY"]             = os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///sankofaeye.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SCAN_OUTPUT_DIR"]         = os.path.join(BASE_DIR, "output")
app.config["MAX_FREE_SCANS_PER_MONTH"] = 1

db           = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "auth.login"

# ── In-memory job registry ─────────────────────────────────────────────────────
# { job_id: { status, progress, domain, pdf_path, exec_path, error, started_at } }
JOBS = {}

# ── Register blueprints ───────────────────────────────────────────────────────
from routes.auth    import auth_bp
from routes.scan    import scan_bp
from routes.reports import reports_bp
from routes.billing import billing_bp

app.register_blueprint(auth_bp)
app.register_blueprint(scan_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(billing_bp)


@app.context_processor
def inject_globals():
    import os
    return {
        "stripe_enabled":   bool(os.getenv("STRIPE_SECRET_KEY")),
        "stripe_pub_key":   os.getenv("STRIPE_PUBLISHABLE_KEY", ""),
        "paystack_enabled": bool(os.getenv("PAYSTACK_SECRET_KEY")),
    }


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))
    return redirect(url_for("auth.login"))


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404,
                           message="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500,
                           message="Internal server error"), 500


# ── Models (defined here for simplicity; move to models.py for scale) ──────────

from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    plan          = db.Column(db.String(20), default="free")   # free/starter/professional
    created_at              = db.Column(db.DateTime, default=datetime.utcnow)
    stripe_customer_id      = db.Column(db.String(64),  nullable=True)
    stripe_subscription_id  = db.Column(db.String(64),  nullable=True)
    scans                   = db.relationship("ScanJob", backref="user", lazy=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    @property
    def scan_limit(self):
        # -1 = unlimited (Enterprise)
        return {"free": 1, "starter": 5, "professional": 20, "enterprise": -1}.get(self.plan, 1)

    def scans_this_month(self):
        now = datetime.utcnow()
        return ScanJob.query.filter_by(user_id=self.id).filter(
            db.extract("year",  ScanJob.created_at) == now.year,
            db.extract("month", ScanJob.created_at) == now.month,
            ScanJob.status == "complete",
        ).count()


class ScanJob(db.Model):
    __tablename__ = "scan_jobs"
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    domain      = db.Column(db.String(255), nullable=False)
    status      = db.Column(db.String(20), default="queued")  # queued/running/complete/failed
    risk_score  = db.Column(db.Integer,  nullable=True)
    risk_rating = db.Column(db.String(20), nullable=True)
    pdf_path    = db.Column(db.String(512), nullable=True)
    exec_path   = db.Column(db.String(512), nullable=True)
    json_path   = db.Column(db.String(512), nullable=True)
    error_msg   = db.Column(db.Text, nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at= db.Column(db.DateTime, nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── App context globals (shared with blueprints via app.config) ────────────────
app.config["JOBS"] = JOBS
app.config["DB"]   = db
app.config["USER_MODEL"]     = User
app.config["SCAN_JOB_MODEL"] = ScanJob


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create a default admin user if no users exist
        if not User.query.first():
            admin = User(email="admin@afriwealthci.com", plan="professional")
            admin.set_password("SankofahEye2026!")
            db.session.add(admin)
            db.session.commit()
            print("[setup] Default admin created: admin@afriwealthci.com")
    app.run(debug=True, host="0.0.0.0", port=8000)