#!/usr/bin/env python3
"""
SankofaEye — admin login diagnostic.
Run from repo root:  python check_admin.py
"""
import os, sys

EMAIL    = "admin@afriwealthci.com"
PASSWORD = "SankofahEye2026!"   # <-- put the EXACT password you're typing at login

HERE    = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(HERE, "sankofaeye_web")
sys.path.insert(0, WEB_DIR)

from app import app, db, User  # noqa: E402

with app.app_context():
    # Which DB file is actually being used?
    print("DB URI:", app.config.get("SQLALCHEMY_DATABASE_URI"))
    eng = db.get_engine() if hasattr(db, "get_engine") else db.engine
    print("DB engine URL:", eng.url)

    users = User.query.all()
    print(f"\nTotal users in DB: {len(users)}")
    for u in users:
        print(f"  - id={u.id}  email={u.email!r}  plan={u.plan}")

    print(f"\nLooking up {EMAIL!r} ...")
    user = User.query.filter_by(email=EMAIL).first()
    if not user:
        print("  NOT FOUND — this email has no row in this DB.")
    else:
        ok = user.check_password(PASSWORD)
        print(f"  found. check_password({PASSWORD!r}) -> {ok}")