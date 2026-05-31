"""
SankofahEye — Multi-Channel Alert Engine
AfriWealth Cyber Intelligence

Delivers security alerts across four channels:

  1. Email (SMTP — already configured)
  2. WhatsApp (Twilio WhatsApp Business API)
  3. SMS (Twilio SMS — Ghana numbers supported)
  4. Webhook (Slack, Teams, custom integrations)

Alert types:
  - NEW_FINDING      : New critical/high finding detected in scheduled scan
  - PHISHING_ALERT   : Lookalike domain or live phishing page detected
  - CERT_EXPIRY      : Certificate expiring within 14 days
  - SUBDOMAIN_NEW    : New subdomain discovered since last scan
  - SCORE_CHANGE     : Risk score changed by ≥10 points
  - BREACH_NEW       : New credential breach detected
  - DARK_WEB_NEW     : New dark web mention detected
  - COMPLIANCE_FAIL  : New regulatory compliance gap detected

Required .env variables:
  TWILIO_ACCOUNT_SID   = AC...
  TWILIO_AUTH_TOKEN    = ...
  TWILIO_FROM_PHONE    = +1234567890   (your Twilio number)
  TWILIO_WHATSAPP_FROM = whatsapp:+14155238886  (Twilio sandbox or approved number)
  ALERT_WEBHOOK_URL    = https://hooks.slack.com/...  (optional)

Alert recipient config is stored per-user in the DB:
  User.alert_email    = comma-separated emails
  User.alert_phone    = E.164 format e.g. +233241234567
  User.alert_channels = json list e.g. ["email","whatsapp","sms"]
"""

import os
import json
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
from utils.logger import SankofahLogger

log = SankofahLogger("alert_engine")

# ── Alert type definitions ─────────────────────────────────────────────────────

ALERT_TYPES = {
    "NEW_FINDING":     {"emoji": "🚨", "urgency": "HIGH"},
    "PHISHING_ALERT":  {"emoji": "🎣", "urgency": "CRITICAL"},
    "CERT_EXPIRY":     {"emoji": "🔐", "urgency": "HIGH"},
    "SUBDOMAIN_NEW":   {"emoji": "🌐", "urgency": "MEDIUM"},
    "SCORE_CHANGE":    {"emoji": "📊", "urgency": "MEDIUM"},
    "BREACH_NEW":      {"emoji": "🔓", "urgency": "CRITICAL"},
    "DARK_WEB_NEW":    {"emoji": "🕵️", "urgency": "HIGH"},
    "COMPLIANCE_FAIL": {"emoji": "⚠️",  "urgency": "HIGH"},
}


# ── Message builder ────────────────────────────────────────────────────────────

def _build_message(alert_type: str, domain: str, detail: str,
                   score: int = None, channel: str = "sms") -> str:
    """
    Build a channel-appropriate alert message.

    SMS/WhatsApp: short (≤320 chars)
    Email/Webhook: full HTML/JSON body
    """
    meta    = ALERT_TYPES.get(alert_type, {"emoji": "⚠️", "urgency": "MEDIUM"})
    emoji   = meta["emoji"]
    urgency = meta["urgency"]
    now     = datetime.utcnow().strftime("%d %b %Y %H:%M UTC")

    if channel in ("sms", "whatsapp"):
        score_str = f" | Score: {score}/100" if score is not None else ""
        msg = (
            f"{emoji} SankofahEye [{urgency}]\n"
            f"Domain: {domain}\n"
            f"{detail}{score_str}\n"
            f"afriwealthci.com\n{now}"
        )
        return msg[:320]  # WhatsApp/SMS safe length

    elif channel == "email_html":
        urgency_colour = {
            "CRITICAL": "#D32F2F",
            "HIGH":     "#F57C00",
            "MEDIUM":   "#FBC02D",
            "LOW":      "#388E3C",
        }.get(urgency, "#757575")

        return f"""
        <html><body style="font-family:Arial,sans-serif;color:#212121;max-width:600px;margin:0 auto;">
        <div style="background:#005F5F;padding:20px;border-bottom:3px solid #FFD700;">
          <h2 style="color:white;margin:0;font-size:18px;">{emoji} SankofahEye Alert</h2>
          <p style="color:#FFD700;margin:4px 0 0;font-size:12px;">AfriWealth Cyber Intelligence</p>
        </div>
        <div style="padding:24px 20px;">
          <div style="background:#FFF3F3;border-left:4px solid {urgency_colour};
                      padding:12px 16px;margin-bottom:20px;border-radius:4px;">
            <strong style="color:{urgency_colour};">{urgency} — {alert_type.replace('_',' ')}</strong>
          </div>
          <p><strong>Domain:</strong> {domain}</p>
          <p style="margin:12px 0;">{detail}</p>
          {f'<p><strong>Current Risk Score:</strong> <span style="color:{urgency_colour};font-size:18px;font-weight:bold;">{score}/100</span></p>' if score is not None else ''}
          <a href="https://afriwealthci.com/dashboard"
             style="display:inline-block;background:#008080;color:white;
                    padding:10px 20px;border-radius:4px;text-decoration:none;
                    font-size:13px;margin-top:8px;">
            View Dashboard →
          </a>
          <p style="font-size:11px;color:#757575;margin-top:20px;">{now}</p>
        </div>
        <div style="background:#F5F5F5;padding:12px 20px;font-size:11px;color:#757575;">
          AfriWealth Cyber Intelligence | afriwealthci.com<br>
          Passive reconnaissance only.
        </div>
        </body></html>
        """

    elif channel == "webhook":
        return json.dumps({
            "type":    alert_type,
            "urgency": urgency,
            "domain":  domain,
            "detail":  detail,
            "score":   score,
            "time":    now,
            "source":  "SankofahEye — AfriWealth Cyber Intelligence",
        })

    return f"{emoji} [{urgency}] {domain}: {detail}"


# ── Channel: Email ─────────────────────────────────────────────────────────────

def send_email_alert(
    recipient: str,
    alert_type: str,
    domain: str,
    detail: str,
    score: int = None,
) -> bool:
    """Send an HTML email alert via configured SMTP."""
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not all([smtp_host, smtp_user, smtp_pass]):
        log.warning("[AlertEngine] SMTP not configured — skipping email alert")
        return False

    meta    = ALERT_TYPES.get(alert_type, {"emoji": "⚠️", "urgency": "MEDIUM"})
    subject = (
        f"{meta['emoji']} [{meta['urgency']}] SankofahEye: "
        f"{alert_type.replace('_', ' ')} — {domain}"
    )

    body = _build_message(alert_type, domain, detail, score, "email_html")

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp_from
        msg["To"]      = recipient
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [recipient], msg.as_string())

        log.info(f"[AlertEngine] ✅ Email sent to {recipient} — {alert_type} / {domain}")
        return True

    except Exception as e:
        log.error(f"[AlertEngine] Email failed: {e}")
        return False


# ── Channel: WhatsApp (Twilio) ─────────────────────────────────────────────────

def send_whatsapp_alert(
    to_phone: str,
    alert_type: str,
    domain: str,
    detail: str,
    score: int = None,
) -> bool:
    """
    Send WhatsApp message via Twilio WhatsApp Business API.

    to_phone: E.164 format — e.g. +233241234567 (Ghana MTN)
    Twilio will prepend 'whatsapp:' automatically.

    Requires:
      TWILIO_ACCOUNT_SID
      TWILIO_AUTH_TOKEN
      TWILIO_WHATSAPP_FROM  (e.g. whatsapp:+14155238886)
    """
    account_sid  = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token   = os.getenv("TWILIO_AUTH_TOKEN")
    from_whatsapp = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")

    if not all([account_sid, auth_token]):
        log.warning("[AlertEngine] Twilio not configured — skipping WhatsApp alert")
        return False

    body = _build_message(alert_type, domain, detail, score, "whatsapp")
    to   = f"whatsapp:{to_phone}" if not to_phone.startswith("whatsapp:") else to_phone

    try:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
        resp = requests.post(
            url,
            auth=(account_sid, auth_token),
            data={"From": from_whatsapp, "To": to, "Body": body},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            log.info(f"[AlertEngine] ✅ WhatsApp sent to {to_phone} — {alert_type}")
            return True
        else:
            log.error(f"[AlertEngine] WhatsApp failed: {resp.status_code} {resp.text[:200]}")
            return False

    except Exception as e:
        log.error(f"[AlertEngine] WhatsApp error: {e}")
        return False


# ── Channel: SMS (Twilio) ──────────────────────────────────────────────────────

def send_sms_alert(
    to_phone: str,
    alert_type: str,
    domain: str,
    detail: str,
    score: int = None,
) -> bool:
    """
    Send SMS via Twilio. Supports Ghana numbers (+233...).

    to_phone: E.164 format — e.g. +233241234567

    Requires:
      TWILIO_ACCOUNT_SID
      TWILIO_AUTH_TOKEN
      TWILIO_FROM_PHONE   (your Twilio number e.g. +14155238886)
    """
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token  = os.getenv("TWILIO_AUTH_TOKEN")
    from_phone  = os.getenv("TWILIO_FROM_PHONE")

    if not all([account_sid, auth_token, from_phone]):
        log.warning("[AlertEngine] Twilio not configured — skipping SMS alert")
        return False

    body = _build_message(alert_type, domain, detail, score, "sms")

    try:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
        resp = requests.post(
            url,
            auth=(account_sid, auth_token),
            data={"From": from_phone, "To": to_phone, "Body": body},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            log.info(f"[AlertEngine] ✅ SMS sent to {to_phone} — {alert_type}")
            return True
        else:
            log.error(f"[AlertEngine] SMS failed: {resp.status_code} {resp.text[:200]}")
            return False

    except Exception as e:
        log.error(f"[AlertEngine] SMS error: {e}")
        return False


# ── Channel: Webhook (Slack / Teams / Custom) ─────────────────────────────────

def send_webhook_alert(
    webhook_url: str,
    alert_type: str,
    domain: str,
    detail: str,
    score: int = None,
) -> bool:
    """
    Send alert to a webhook URL (Slack, Microsoft Teams, custom).

    Auto-detects Slack vs Teams vs generic based on URL pattern.
    """
    if not webhook_url:
        return False

    meta    = ALERT_TYPES.get(alert_type, {"emoji": "⚠️", "urgency": "MEDIUM"})
    emoji   = meta["emoji"]
    urgency = meta["urgency"]

    urgency_colour = {
        "CRITICAL": "#D32F2F",
        "HIGH":     "#F57C00",
        "MEDIUM":   "#FBC02D",
        "LOW":      "#388E3C",
    }.get(urgency, "#757575")

    score_str = f" | Score: {score}/100" if score is not None else ""

    try:
        # Slack format
        if "hooks.slack.com" in webhook_url:
            payload = {
                "attachments": [{
                    "color":  urgency_colour,
                    "title":  f"{emoji} SankofahEye: {alert_type.replace('_', ' ')} — {domain}",
                    "text":   f"{detail}{score_str}",
                    "footer": "AfriWealth Cyber Intelligence | afriwealthci.com",
                    "ts":     int(datetime.utcnow().timestamp()),
                    "fields": [
                        {"title": "Urgency", "value": urgency,  "short": True},
                        {"title": "Domain",  "value": domain,   "short": True},
                    ]
                }]
            }

        # Microsoft Teams format
        elif "webhook.office.com" in webhook_url or "teams" in webhook_url.lower():
            payload = {
                "@type":    "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": urgency_colour.replace("#", ""),
                "summary":  f"SankofahEye Alert: {domain}",
                "sections": [{
                    "activityTitle":    f"{emoji} {alert_type.replace('_', ' ')}",
                    "activitySubtitle": domain,
                    "activityText":     f"{detail}{score_str}",
                    "facts": [
                        {"name": "Urgency", "value": urgency},
                        {"name": "Source",  "value": "AfriWealth Cyber Intelligence"},
                    ]
                }]
            }

        # Generic JSON
        else:
            payload = json.loads(_build_message(
                alert_type, domain, detail, score, "webhook"
            ))

        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code in (200, 201, 204):
            log.info(f"[AlertEngine] ✅ Webhook sent — {alert_type} / {domain}")
            return True
        else:
            log.error(f"[AlertEngine] Webhook failed: {resp.status_code}")
            return False

    except Exception as e:
        log.error(f"[AlertEngine] Webhook error: {e}")
        return False


# ── Unified dispatcher ─────────────────────────────────────────────────────────

def dispatch_alert(
    alert_type: str,
    domain: str,
    detail: str,
    score: int = None,
    channels: list = None,
    email: str = None,
    phone: str = None,
    webhook_url: str = None,
) -> dict:
    """
    Dispatch an alert across all configured channels.

    Args:
        alert_type:  One of ALERT_TYPES keys
        domain:      Target domain
        detail:      Human-readable description of the alert
        score:       Current risk score (optional)
        channels:    List of channels to use: ["email","whatsapp","sms","webhook"]
                     Defaults to all configured channels
        email:       Override recipient email
        phone:       Override recipient phone (E.164)
        webhook_url: Override webhook URL

    Returns:
        dict of channel → success bool
    """
    if channels is None:
        channels = ["email", "whatsapp", "sms", "webhook"]

    results = {}

    if "email" in channels and email:
        results["email"] = send_email_alert(email, alert_type, domain, detail, score)

    if "whatsapp" in channels and phone:
        results["whatsapp"] = send_whatsapp_alert(phone, alert_type, domain, detail, score)

    if "sms" in channels and phone:
        results["sms"] = send_sms_alert(phone, alert_type, domain, detail, score)

    if "webhook" in channels:
        url = webhook_url or os.getenv("ALERT_WEBHOOK_URL")
        if url:
            results["webhook"] = send_webhook_alert(url, alert_type, domain, detail, score)

    delivered = [ch for ch, ok in results.items() if ok]
    failed    = [ch for ch, ok in results.items() if not ok]

    log.info(
        f"[AlertEngine] {alert_type} / {domain} — "
        f"Delivered: {delivered} | Failed: {failed}"
    )

    return results