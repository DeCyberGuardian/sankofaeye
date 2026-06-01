# SankofaEye 👁️
### Passive Exposure Intelligence Platform
**By AfriWealth Cyber Intelligence**

[![Python](https://img.shields.io/badge/Python-3.12+-008080?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-008080?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-FFD700?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-008080?style=flat-square)](https://github.com)
[![Status](https://img.shields.io/badge/Status-Active-FFD700?style=flat-square)](https://github.com)
[![Version](https://img.shields.io/badge/Version-1.0.0-008080?style=flat-square)](https://github.com)

> *"Go back and fetch it."* — Sankofa proverb.  
> Look back at what is exposed before an adversary does.

---

SankofaEye is a **passive exposure intelligence platform** built for cyber threat intelligence practitioners operating in Ghana and the broader West African digital ecosystem.

It chains 10 open-source intelligence modules to produce a structured **Exposure Intelligence Report** — branded, PDF-formatted, with MITRE ATT&CK mappings, West Africa threat actor context, mobile money exposure analysis, regulatory compliance mapping, phishing infrastructure detection, and multi-channel security alerting.

Available as a **CLI tool** and a **Flask web application** with multi-user support, scan scheduling, remediation tracking, peer benchmarking, and tiered plans (Free → Starter → Professional → Enterprise).

**No active exploitation. No direct target interaction. Pure passive OSINT.**

---

## Contents

- [What SankofaEye Produces](#what-sankofaeye-produces)
- [Intelligence Modules](#intelligence-modules)
- [Installation](#installation)
- [Usage](#usage)
- [Web Interface](#web-interface)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Plans & Pricing](#plans--pricing)
- [Ethical & Legal Guidelines](#ethical--legal-guidelines)
- [Roadmap](#roadmap)
- [Author](#author)

---

## What SankofaEye Produces

Every scan generates two files — a full intelligence report and a raw data export:

```
output/
├── SankofaEye_ghipss.com_20260527_113800.pdf                  ← 14-page branded intelligence report
├── SankofaEye_ghipss.com_20260527_113800_executive_summary.pdf ← Board-ready one-pager
└── SankofaEye_ghipss.com_20260527_113800.json                 ← Structured findings (machine-readable)
```

### Full Intelligence Report (14+ pages)

| Section | Content |
|---------|---------|
| Cover & Risk Score | 0–100 score, severity rating, finding count, MITRE technique count |
| Executive Summary | Plain-English overview — suitable for IT management |
| Findings & Risk Analysis | Detail, recommendation, MITRE ATT&CK, full attack scenario narrative |
| Mobile Money Exposure | MoMo subdomain patterns, USSD/settlement/API/back-office, OPERA1ER scenarios |
| Regulatory Compliance | BoG CISD / NCA Guidelines / DPC Act 843 — score (%) + control gaps with section refs |
| West Africa Threat Intelligence | Cross-referenced actors, historical incidents, IOC pattern matches |
| Subdomain Inventory | All enumerated subdomains |
| Exposed Services | Open ports, CVEs, banners (Censys) |
| Credential Exposure | Breached accounts (HIBP) |
| Dark Web Monitoring | Indexed mentions (Ahmia) |
| Infostealer Exposure | Compromised staff credentials (HudsonRock) |
| Technology Fingerprint | Detected tech stack + CVE risk class mapping |
| DNS & Email Security | SPF / DKIM / DMARC analysis + A–F Email Scorecard |
| SSL/TLS Analysis | Certificate validity, expiry, weak protocol detection |
| Remediation Action Plan | 3-track plan: Track 1 (72h) / Track 2 (30d) / Track 3 (90d) |
| MITRE ATT&CK Mapping | All techniques detected in the scan |

### Executive One-Pager

Single-page PDF for CISO and board. Plain English, no CVE numbers. Risk score, top findings, immediate actions.

---

## Intelligence Modules

| # | Module | Source | Data Collected | API Key |
|---|--------|--------|----------------|---------|
| 1 | Subfinder | ProjectDiscovery | Subdomains via cert transparency, DNS datasets | No |
| 2 | theHarvester | Laramies | Emails, hostnames, IPs from search engines | No |
| 3 | Censys | Censys.io | Open ports, services, banners, CVEs | Yes (free) |
| 4 | HIBP | HaveIBeenPwned | Breached email accounts by domain | Yes (~$3.50/mo) |
| 5 | VirusTotal | VirusTotal | Domain reputation, malicious votes | Yes (free) |
| 6 | URLScan.io | URLScan | Passive web scans, technology fingerprinting | Yes (free) |
| 7 | HudsonRock | Cavalier API | Infostealer / malware log credential exposure | No |
| 8 | Dark Web | Ahmia.fi | Dark web indexed mentions | No |
| 9 | DNS Security | dnspython | SPF, DMARC, DKIM, MX, NS records | No |
| 10 | SSL/TLS | ssl / requests | Certificate validity, expiry, weak protocols | No |

**Ghana-specific modules (unique to SankofaEye):**

| Module | What It Does |
|--------|-------------|
| MoMo Exposure | 30 Mobile Money subdomain patterns — USSD, settlement, back-office, auth, API. MTN MoMo, Telecel Cash, AirtelTigo Money. |
| Compliance Mapper | Maps every finding to BoG CISD, NCA Guidelines, and DPC Act 843. Control ID, section reference, severity, remediation. |
| WA Threat DB | Cross-references scan profile against 6 tracked West African threat actors with sector detection and IOC matching. |
| Tech Fingerprint | URLScan-based tech stack detection (30+ patterns). CVE risk class mapping. |
| Email Scorecard | A–F grade on SPF / DKIM / DMARC. Weighted 0–100 score. |
| Phishing Detector | Monitors crt.sh, WHOIS, and URLScan for lookalike domains targeting your brand. Pre-crime intelligence. |
| Benchmarking | Anonymised peer comparison — where does your score rank within your sector in Ghana? |
| Remediation Tracker | Tracks finding lifecycle: OPEN → IN_PROGRESS → RESOLVED → VERIFIED → REOPENED. Auto-verifies fixes. |

---

## Installation

### Prerequisites

- macOS or Linux
- Python 3.12+
- Homebrew (macOS) — [install](https://brew.sh)

### Step 1 — Clone the repository

```bash
git clone https://github.com/DeCyberGuardian/sankofaeye.git
cd sankofaeye
```

### Step 2 — Create and activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4 — Install Subfinder

```bash
# macOS
brew install subfinder

# Linux
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify
subfinder -version
```

### Step 5 — Install theHarvester

```bash
pip install git+https://github.com/laramies/theHarvester.git
```

### Step 6 — Configure API keys

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

```env
# Core OSINT modules
CENSYS_API_TOKEN=your_censys_personal_access_token
CENSYS_ORG_ID=your_censys_organization_id
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLSCAN_API_KEY=your_urlscan_api_key
HIBP_API_KEY=your_hibp_api_key

# Web interface
FLASK_SECRET_KEY=your_random_secret_key
DATABASE_URL=sqlite:///sankofaeye.db

# Alerts — Twilio (Email + WhatsApp + SMS)
TWILIO_ACCOUNT_SID=AC...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM_PHONE=+1...
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
ALERT_WEBHOOK_URL=https://hooks.slack.com/...

# Domain monitoring
WHOISXML_API_KEY=your_whoisxml_key

# Payment (Paystack — Ghana-first)
PAYSTACK_SECRET_KEY=sk_live_...
PAYSTACK_PUBLIC_KEY=pk_live_...

# Payment (Stripe — optional)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_STARTER_PRICE_ID=price_...
STRIPE_PROFESSIONAL_PRICE_ID=price_...
STRIPE_ENTERPRISE_PRICE_ID=price_...

# Scheduled scan email delivery
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=reports@afriwealthci.com
SMTP_PASSWORD=your_app_password
APP_BASE_URL=https://yourdomain.com
```

| Key | Where to Get | Cost |
|-----|-------------|------|
| `CENSYS_API_TOKEN` | [search.censys.io](https://search.censys.io) → Account → API | Free |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | Free |
| `URLSCAN_API_KEY` | [urlscan.io/user/signup](https://urlscan.io/user/signup) | Free |
| `HIBP_API_KEY` | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) | ~$3.50/mo |
| `TWILIO_ACCOUNT_SID` | [twilio.com/console](https://twilio.com/console) | Free trial |
| `WHOISXML_API_KEY` | [whoisxmlapi.com](https://whoisxmlapi.com) | Free tier |
| `PAYSTACK_SECRET_KEY` | [dashboard.paystack.com](https://dashboard.paystack.com) | Free (transaction fees) |

---

## Usage

### CLI

```bash
# Activate virtual environment
source venv/bin/activate

# Scan a single domain
python sankofaeye.py --domain example.com

# Scan multiple domains
python sankofaeye.py --domain gcb.com.gh mtn.com.gh bog.gov.gh

# Custom output directory
python sankofaeye.py --domain example.com --output ./reports

# Regenerate PDFs from an existing JSON (no rescan)
python sankofaeye.py --report-only output/SankofaEye_ghipss.com_20260527.json

# Custom config file
python sankofaeye.py --domain example.com --config config.yaml
```

### Web Interface

```bash
# Run from the sankofaeye/ root directory (not from inside sankofaeye_web/)
python sankofaeye_web/app.py

# Access at http://localhost:8080
# Default admin: admin@afriwealthci.com / SankofaEye2026!
```

> **macOS note:** Disable AirPlay Receiver in System Settings if port 5000 is in use,
> or kill it with `lsof -ti:5000 | xargs kill -9`, or change port to 8080 in `app.py`.

### Scheduled Scans

```bash
# Run in a separate terminal alongside the Flask app
python scheduler/scan_scheduler.py
```

Schedules: Enterprise = daily | Professional = weekly | Starter = monthly.
Sends email + WhatsApp + SMS when new findings are detected.

---

## Web Interface

| Feature | Details |
|---------|---------|
| Authentication | Register / login / logout with secure password hashing |
| Dashboard | Scan form → recent scans → compliance → WA threat context → MoMo exposure → plans |
| Scan Progress | Live polling every 3s, module checklist, real-time score reveal |
| Report Downloads | Full PDF, Executive PDF, raw JSON — per scan |
| Findings Viewer | In-browser findings table with severity badges and stats |
| Compliance Widget | BoG / NCA / DPC scores with control gap list from last scan |
| WA Threat Intel | Threat actor cards — relevance, motivation, MITRE techniques |
| MoMo Exposure | Detected MoMo services and risk findings from last scan |
| Remediation Tracker | Track finding status (Open → In Progress → Resolved → Verified) per scan |
| Alert Settings | Configure Email, WhatsApp, SMS, and Webhook notification channels |
| Peer Benchmarking | See how your score compares to sector peers in Ghana |
| Plans & Billing | Free / Starter / Professional / Enterprise with Paystack + Stripe |
| Scheduler | Automated scans, delta reports, multi-channel delivery |

---

## Project Structure

```
sankofaeye/
├── sankofaeye.py                        # Main CLI orchestrator
├── config.yaml                          # Module toggles, risk weights, brand config
├── requirements.txt                     # Python dependencies
├── .env.example                         # API key + config template
├── .gitignore
│
├── modules/
│   ├── subfinder_module.py              # Subdomain enumeration
│   ├── harvester_module.py              # Email + host harvesting
│   ├── censys_module.py                 # Exposed services (Censys API)
│   ├── hibp_module.py                   # Credential leak check (HIBP)
│   ├── vt_urlscan_module.py             # Domain reputation + tech fingerprint
│   ├── darkweb_module.py                # Dark web mention search (Ahmia)
│   ├── hudsonrock_module.py             # Infostealer credential exposure
│   ├── dns_module.py                    # DNS + email security analysis
│   └── momo_module.py                   # Mobile Money exposure (Ghana-specific)
│
├── utils/
│   ├── aggregator.py                    # Normalise + merge all module findings
│   ├── risk_scorer.py                   # Risk scoring + MITRE ATT&CK mapping
│   ├── compliance_mapper.py             # BoG CISD / NCA / DPC Act 843 mapping
│   ├── tech_fingerprint.py              # Technology stack detection + CVE mapping
│   ├── email_scorer.py                  # A–F Email Security Scorecard
│   ├── benchmarking.py                  # Anonymised peer sector benchmarking
│   ├── remediation_tracker.py           # Finding lifecycle tracking + auto-verification
│   ├── logger.py                        # Coloured console + file logging
│   └── validator.py                     # Domain input validation
│
├── reports/
│   ├── pdf_generator.py                 # Full 14-page AfriWealth CI branded report
│   └── executive_onepager.py            # Board-ready executive summary PDF
│
├── intel/
│   ├── wa_threatdb.json                 # West Africa threat actor database
│   ├── wa_threatdb_module.py            # Threat DB cross-reference engine
│   └── benchmark_db.json               # Anonymised sector benchmark scores (auto-built)
│
├── monitoring/
│   ├── __init__.py
│   └── phishing_detector.py            # crt.sh + WHOIS + URLScan lookalike monitoring
│
├── alerts/
│   ├── __init__.py
│   └── alert_engine.py                 # Email + WhatsApp + SMS + Webhook dispatcher
│
├── scheduler/
│   └── scan_scheduler.py               # Recurring scans + delta reports + email/alert delivery
│
├── sankofaeye_web/                      # Flask web application
│   ├── app.py                           # Application factory, models, blueprints
│   ├── routes/
│   │   ├── auth.py                      # Login, register, logout
│   │   ├── scan.py                      # Dashboard, scan submission, progress polling
│   │   ├── reports.py                   # Report listing and downloads
│   │   ├── billing.py                   # Paystack + Stripe payment integration
│   │   └── tracker.py                   # Remediation tracker + alert settings
│   └── templates/
│       ├── base.html                    # AfriWealth CI branded base layout
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html               # Main dashboard with all intelligence widgets
│       ├── scan_progress.html           # Live scan progress with module checklist
│       ├── reports.html                 # Report listing
│       ├── findings.html                # In-browser findings viewer
│       ├── tracker.html                 # Remediation tracker view
│       ├── alert_settings.html          # Alert channel configuration
│       └── error.html
│
├── output/                              # Generated reports — gitignored
├── logs/                                # Scan logs — gitignored
└── samples/                             # Redacted example report
```

---

## Configuration

`config.yaml` controls all module settings, brand, output, and alert recipients:

```yaml
brand:
  tool:     SankofaEye
  version:  1.0.0
  name:     AfriWealth Cyber Intelligence
  analyst:  DeCyberGuardian
  website:  https://afriwealthci.com

modules:
  subfinder:    true
  theharvester: true
  shodan:       true
  hibp:         true
  virustotal:   true
  urlscan:      true
  darkweb:      true
  hudsonrock:   true
  dns:          true
  ssl:          true

timeouts:
  subfinder:    60
  theharvester: 90
  shodan:       30
  hibp:         20
  virustotal:   30
  darkweb:      45
  hudsonrock:   30
  dns:          30
  ssl:          45

output:
  pdf_report:      true
  json_dump:       true
  log_directory:   logs/
  log_level:       INFO

# Alert recipients for CLI scans
alerts:
  email: security@yourorganisation.com
  phone: +233241234567          # E.164 format — Ghana MTN example
  channels: [email, whatsapp, sms]
  webhook: https://hooks.slack.com/...
```

---

## Plans & Pricing

| Plan | Price | Scans | Key Features |
|------|-------|-------|-------------|
| **Free** | $0 | 1/mo | Full PDF report, executive one-pager, all 10 modules |
| **Starter** | $49/mo | 5/mo | Monthly scheduling, email + WhatsApp delivery, delta reports |
| **Professional** | $149/mo | 20/mo | Weekly scans, WA threat context, BoG/NCA/DPC mapping, peer benchmarking |
| **Enterprise** | $499/mo | Unlimited | Aegis-INT DRIB briefs, dedicated analyst support, custom regulatory mapping, daily scans |

Payment via **Paystack** (MTN MoMo, Telecel Cash, AirtelTigo Money, card, bank transfer) and **Stripe** (international card).

---

## Ethical & Legal Guidelines

> **Authorised use only.**

SankofaEye performs passive reconnaissance only — no packets are sent to target systems.

- Only scan domains you **own** or have **explicit written authorisation** to assess
- Handle credential data and report outputs with strict access controls — all reports are **CONFIDENTIAL**
- Comply with Ghana's **Data Protection Act 2012 (Act 843)** when processing personal data from breach results
- Respect all API provider terms of service and rate limits
- SankofaEye findings are intelligence, not legal advice

---

## Roadmap

**Completed ✅**
- [x] 10-module passive OSINT pipeline
- [x] Risk scoring engine + MITRE ATT&CK mapping + 3-track remediation
- [x] Branded 14-page PDF report + executive one-pager
- [x] Email Security Scorecard (A–F)
- [x] Technology fingerprinting + CVE class mapping
- [x] Mobile Money exposure module (30 patterns — MTN MoMo / Telecel / AirtelTigo)
- [x] Regulatory compliance mapper (BoG CISD / NCA / DPC Act 843 — 19 controls)
- [x] West Africa Threat Intelligence database (6 actors + incident history)
- [x] `--report-only` mode
- [x] Flask web interface — multi-user, plans, billing
- [x] Paystack integration (Ghana-first: MTN MoMo, card, bank transfer)
- [x] Stripe integration skeleton (international)
- [x] Scheduled recurring scans + delta reports + email delivery
- [x] 4-tier pricing: Free / Starter / Professional / Enterprise (Aegis-INT)
- [x] Phishing infrastructure detection (crt.sh + WHOIS + URLScan — pre-crime intelligence)
- [x] Multi-channel alerts: Email + WhatsApp + SMS + Webhook (Slack/Teams)
- [x] Peer benchmarking (anonymised sector score comparison)
- [x] Remediation tracker (OPEN → IN_PROGRESS → RESOLVED → VERIFIED → REOPENED)
- [x] AfriWealth CI company letterhead (.docx)

**In Progress 🔄**
- [ ] Aegis-INT DRIB integration (Enterprise — decision-ready intelligence briefs)
- [ ] Attack path visualisation (Ghana-specific kill chain diagrams per scan)
- [ ] Obsidian vault export (scan findings as structured markdown notes)
- [ ] Paystack live account + Stripe activation
- [ ] Hostinger company email migration

**Planned 📋**
- [ ] Dark web persona monitoring (executive names + brand terms on Telegram/forums)
- [ ] Supplier / third-party risk scoring (vendor ecosystem passive assessment)
- [ ] Natural language query — "Which findings increase our BEC risk most?"
- [ ] Ghana Threat Calendar (election proximity, quarter-end, national events)
- [ ] REST API (`/api/v1/scan`) for programmatic access
- [ ] SIEM integration (Splunk HEC / Elastic ECS export)
- [ ] Multi-domain portfolio view for client management
- [ ] WhatsApp report delivery (full PDF via WhatsApp)
- [ ] Mobile app (React Native)

---

## Author

**Stephen Oppong (DeCyberGuardian)**
Founder & Lead Analyst — AfriWealth Cyber Intelligence
Cyber Threat Intelligence Practitioner | Accra, Ghana

[![LinkedIn](https://img.shields.io/badge/LinkedIn-DeCyberGuardian-008080?style=flat-square&logo=linkedin)](https://linkedin.com/in/decyberguardian)
[![X](https://img.shields.io/badge/X-@DeCyberGuardian-FFD700?style=flat-square&logo=x)](https://x.com/decyberguardian)
[![Website](https://img.shields.io/badge/Website-afriwealthci.com-008080?style=flat-square)](https://afriwealthci.com)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with 🔍 in Ghana for the African digital ecosystem.*  
*Passive reconnaissance only. No active exploitation was performed in the making of this platform.*