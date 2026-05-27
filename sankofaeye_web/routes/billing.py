"""
SankofahEye Web — Billing Routes
AfriWealth Cyber Intelligence

Dual payment integration:
  - Paystack (primary) — MTN MoMo, Telecel, AirtelTigo, card, bank transfer
  - Stripe (secondary) — international card payments

Paystack is Ghana-first: supports all local payment methods,
no US/EU entity required, GHS and USD supported.

Required .env variables (Paystack):
    PAYSTACK_SECRET_KEY       sk_live_... or sk_test_...
    PAYSTACK_PUBLIC_KEY       pk_live_... or pk_test_...

Required .env variables (Stripe — optional):
    STRIPE_SECRET_KEY         sk_live_... or sk_test_...
    STRIPE_PUBLISHABLE_KEY    pk_live_... or pk_test_...
    STRIPE_WEBHOOK_SECRET     whsec_...
    STRIPE_STARTER_PRICE_ID       price_...
    STRIPE_PROFESSIONAL_PRICE_ID  price_...
    STRIPE_ENTERPRISE_PRICE_ID    price_...

Paystack webhook URL to register:
    https://yourdomain.com/billing/paystack/webhook
"""

import os
import json
import hmac
import hashlib
import requests
from datetime import datetime

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, jsonify, current_app)
from flask_login import login_required, current_user

billing_bp = Blueprint("billing", __name__, url_prefix="/billing")

# ── Plan metadata ──────────────────────────────────────────────────────────────

PLANS = {
    "starter": {
        "name":       "Starter",
        "amount_usd": 49,
        "amount_ghs": 600,   # approx — update with live rate
        "interval":   "monthly",
    },
    "professional": {
        "name":       "Professional",
        "amount_usd": 149,
        "amount_ghs": 1850,
        "interval":   "monthly",
    },
    "enterprise": {
        "name":       "Enterprise",
        "amount_usd": 499,
        "amount_ghs": 6200,
        "interval":   "monthly",
    },
}

# ── Provider availability ──────────────────────────────────────────────────────

def _paystack_enabled():
    return bool(os.getenv("PAYSTACK_SECRET_KEY"))

def _stripe_enabled():
    return bool(os.getenv("STRIPE_SECRET_KEY"))

def _any_payment_enabled():
    return _paystack_enabled() or _stripe_enabled()


# ── Paystack helpers ───────────────────────────────────────────────────────────

PAYSTACK_BASE = "https://api.paystack.co"

def _paystack_headers():
    return {
        "Authorization": f"Bearer {os.getenv('PAYSTACK_SECRET_KEY')}",
        "Content-Type":  "application/json",
    }


def _paystack_init_transaction(email: str, plan: str, callback_url: str,
                                user_id: int) -> dict:
    """
    Initialise a Paystack transaction.
    Returns dict with authorization_url and reference.
    """
    plan_meta = PLANS[plan]
    # Paystack amounts are in pesewas (GHS × 100)
    amount_pesewas = plan_meta["amount_ghs"] * 100

    payload = {
        "email":        email,
        "amount":       amount_pesewas,
        "currency":     "GHS",
        "callback_url": callback_url,
        "metadata": {
            "user_id":  user_id,
            "plan":     plan,
            "platform": "sankofaeye",
        },
        "channels": ["mobile_money", "card", "bank_transfer"],
    }

    resp = requests.post(
        f"{PAYSTACK_BASE}/transaction/initialize",
        headers=_paystack_headers(),
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("status"):
        raise ValueError(data.get("message", "Paystack initialisation failed"))
    return data["data"]


def _paystack_verify(reference: str) -> dict:
    """Verify a Paystack transaction by reference."""
    resp = requests.get(
        f"{PAYSTACK_BASE}/transaction/verify/{reference}",
        headers=_paystack_headers(),
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("status"):
        raise ValueError(data.get("message", "Paystack verification failed"))
    return data["data"]


# ── Stripe helpers ─────────────────────────────────────────────────────────────

PRICE_TO_PLAN = {
    os.getenv("STRIPE_STARTER_PRICE_ID",      "price_starter_placeholder"):      "starter",
    os.getenv("STRIPE_PROFESSIONAL_PRICE_ID", "price_professional_placeholder"): "professional",
    os.getenv("STRIPE_ENTERPRISE_PRICE_ID",   "price_enterprise_placeholder"):   "enterprise",
}
PLAN_TO_STRIPE_PRICE = {v: k for k, v in PRICE_TO_PLAN.items()}


def _stripe():
    if not _stripe_enabled():
        return None
    import stripe
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
    return stripe


# ── Upgrade helper (shared by both providers) ─────────────────────────────────

def _upgrade_user(user_id: int, plan: str, db):
    from app import User
    user = db.session.get(User, user_id)
    if user:
        user.plan = plan
        db.session.commit()
        return True
    return False


# ── Routes ─────────────────────────────────────────────────────────────────────

@billing_bp.route("/checkout/<plan>")
@login_required
def checkout(plan):
    """Route to best available payment provider."""
    if plan not in PLANS:
        flash("Invalid plan.", "error")
        return redirect(url_for("scan.dashboard"))

    if _paystack_enabled():
        return redirect(url_for("billing.paystack_checkout", plan=plan))
    elif _stripe_enabled():
        return redirect(url_for("billing.stripe_checkout", plan=plan))
    else:
        flash("Payment processing is not yet configured. "
              "Contact hello@afriwealthci.com to upgrade.", "warning")
        return redirect(url_for("scan.dashboard"))


# ── Paystack routes ────────────────────────────────────────────────────────────

@billing_bp.route("/paystack/checkout/<plan>")
@login_required
def paystack_checkout(plan):
    """Initiate Paystack payment — redirects to Paystack hosted checkout."""
    if not _paystack_enabled():
        flash("Paystack not configured.", "error")
        return redirect(url_for("scan.dashboard"))

    if plan not in PLANS:
        flash("Invalid plan.", "error")
        return redirect(url_for("scan.dashboard"))

    try:
        callback = url_for("billing.paystack_callback", _external=True)
        txn      = _paystack_init_transaction(
            email=current_user.email,
            plan=plan,
            callback_url=callback,
            user_id=current_user.id,
        )
        return redirect(txn["authorization_url"], code=303)

    except Exception as e:
        flash(f"Payment error: {e}", "error")
        return redirect(url_for("scan.dashboard"))


@billing_bp.route("/paystack/callback")
@login_required
def paystack_callback():
    """Paystack redirects here after payment attempt."""
    reference = request.args.get("reference", "")
    if not reference:
        flash("Invalid payment reference.", "error")
        return redirect(url_for("scan.dashboard"))

    try:
        txn    = _paystack_verify(reference)
        status = txn.get("status")

        if status == "success":
            meta    = txn.get("metadata", {})
            user_id = meta.get("user_id", current_user.id)
            plan    = meta.get("plan", "")
            db      = current_app.config["DB"]

            if plan and _upgrade_user(int(user_id), plan, db):
                flash(
                    f"Payment successful! Your plan has been upgraded to "
                    f"{PLANS[plan]['name']}. Welcome aboard.",
                    "success"
                )
            else:
                flash("Payment received but plan upgrade failed. "
                      "Contact hello@afriwealthci.com.", "warning")
        else:
            flash(f"Payment not completed (status: {status}). "
                  "No charge was made.", "warning")

    except Exception as e:
        flash(f"Payment verification failed: {e}", "error")

    return redirect(url_for("scan.dashboard"))


@billing_bp.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    """
    Paystack webhook — server-side payment confirmation.
    Register at: https://dashboard.paystack.com/#/settings/developer
    URL: https://yourdomain.com/billing/paystack/webhook
    """
    secret = os.getenv("PAYSTACK_SECRET_KEY", "")
    sig    = request.headers.get("X-Paystack-Signature", "")
    body   = request.get_data()

    # Verify signature
    expected = hmac.new(secret.encode(), body, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return jsonify({"error": "Invalid signature"}), 400

    event = request.get_json(force=True)
    db    = current_app.config["DB"]

    if event.get("event") == "charge.success":
        data    = event.get("data", {})
        meta    = data.get("metadata", {})
        user_id = meta.get("user_id")
        plan    = meta.get("plan")

        if user_id and plan and plan in PLANS:
            _upgrade_user(int(user_id), plan, db)

    return jsonify({"status": "ok"}), 200


# ── Stripe routes ──────────────────────────────────────────────────────────────

@billing_bp.route("/stripe/checkout/<plan>")
@login_required
def stripe_checkout(plan):
    """Initiate Stripe Checkout session."""
    if not _stripe_enabled():
        flash("Stripe not configured.", "error")
        return redirect(url_for("scan.dashboard"))

    stripe   = _stripe()
    db       = current_app.config["DB"]
    User     = current_app.config["USER_MODEL"]

    try:
        user = db.session.get(User, current_user.id)
        if not user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=user.email,
                metadata={"user_id": str(user.id)},
            )
            user.stripe_customer_id = customer.id
            db.session.commit()

        price_id = PLAN_TO_STRIPE_PRICE.get(plan, "")
        if not price_id or "placeholder" in price_id:
            flash("Stripe price not configured. Contact hello@afriwealthci.com.", "warning")
            return redirect(url_for("scan.dashboard"))

        session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=url_for("billing.stripe_success",
                                _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("scan.dashboard", _external=True),
            metadata={"user_id": str(current_user.id), "plan": plan},
        )
        return redirect(session.url, code=303)

    except Exception as e:
        flash(f"Payment error: {e}", "error")
        return redirect(url_for("scan.dashboard"))


@billing_bp.route("/stripe/success")
@login_required
def stripe_success():
    flash("Payment successful! Your plan has been upgraded.", "success")
    return redirect(url_for("scan.dashboard"))


@billing_bp.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    """Stripe webhook handler."""
    if not _stripe_enabled():
        return jsonify({"status": "disabled"}), 200

    stripe         = _stripe()
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    payload        = request.get_data()
    sig            = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, webhook_secret)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    db   = current_app.config["DB"]
    User = current_app.config["USER_MODEL"]
    data = event["data"]["object"]

    if event["type"] == "checkout.session.completed":
        user_id = data.get("metadata", {}).get("user_id")
        plan    = data.get("metadata", {}).get("plan")
        if user_id and plan:
            _upgrade_user(int(user_id), plan, db)

    elif event["type"] == "customer.subscription.deleted":
        customer_id = data.get("customer")
        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.plan = "free"
            db.session.commit()

    return jsonify({"status": "ok"}), 200


# ── Customer portal (Stripe only) ─────────────────────────────────────────────

@billing_bp.route("/portal")
@login_required
def customer_portal():
    """Stripe customer portal for subscription management."""
    if not _stripe_enabled():
        flash("To manage your subscription, contact hello@afriwealthci.com.", "warning")
        return redirect(url_for("scan.dashboard"))

    stripe = _stripe()
    db     = current_app.config["DB"]
    User   = current_app.config["USER_MODEL"]
    user   = db.session.get(User, current_user.id)

    if not user.stripe_customer_id:
        flash("No billing account found. Please subscribe first.", "warning")
        return redirect(url_for("scan.dashboard"))

    try:
        session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=url_for("scan.dashboard", _external=True),
        )
        return redirect(session.url, code=303)
    except Exception as e:
        flash(f"Billing portal error: {e}", "error")
        return redirect(url_for("scan.dashboard"))