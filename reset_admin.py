#!/usr/bin/env python3
"""
SankofaEye — one-off admin reset / create.

Run from the repo root:
    python reset_admin.py

Edit ADMIN_EMAIL / ADMIN_PASSWORD below first.
- If the user exists  -> password is reset (and plan bumped to professional).
- If it doesn't exist -> a new professional admin is created.
Existing scan history is left untouched.
"""

import os
import sys

# ── EDIT THESE ──────────────────────────────────────────────
ADMIN_EMAIL    = "stephen@afriwealthintel.com"
ADMIN_PASSWORD = "SankofaEye2026!"
ADMIN_PLAN     = "professional"   # free | starter | professional | enterprise
# ────────────────────────────────────────────────────────────

# Make the web app importable (app.py lives in sankofaeye_web/)
HERE     = os.path.dirname(os.path.abspath(__file__))
WEB_DIR  = os.path.join(HERE, "sankofaeye_web")
sys.path.insert(0, WEB_DIR)

from app import app, db, User  # noqa: E402

with app.app_context():
    db.create_all()  # safe no-op if tables already exist

    user = User.query.filter_by(email=ADMIN_EMAIL).first()
    if user:
        user.set_password(ADMIN_PASSWORD)
        user.plan = ADMIN_PLAN
        action = "reset"
    else:
        user = User(email=ADMIN_EMAIL, plan=ADMIN_PLAN)
        user.set_password(ADMIN_PASSWORD)
        db.session.add(user)
        action = "created"

    db.session.commit()
    print(f"[reset_admin] {action} -> {ADMIN_EMAIL} (plan: {ADMIN_PLAN})")
    print(f"[reset_admin] login with: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")