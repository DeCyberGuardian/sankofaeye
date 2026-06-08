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

It chains 10 open-source intelligence modules to produce a structured **Exposure Intelligence Report** — branded, PDF-formatted, with MITRE ATT&CK mappings, West Africa threat actor context, mobile money exposure analysis, regulatory compliance mapping, phishing infrastructure detection, an inferred attack path, supplier risk scoring, and multi-channel security alerting.

It is **sector-aware** — a media company is not assessed as a bank. Findings, framing, and regulatory mapping adapt to the target's sector (Government, Financial, Telecom, Healthcare, Education, or Commercial), with auto-detection plus manual override.

Available as a **CLI tool**, a **Flask web application** (multi-user, scan scheduling, remediation tracking, peer benchmarking, tiered plans), and a **REST API** with Splunk/Elastic SIEM export.

**No active exploitation. No direct target interaction. Pure passive OSINT.**

---

## Contents

- [What SankofaEye Produces](#what-sankofaeye-produces)
- [Intelligence Modules](#intelligence-modules)
- [Sector-Aware Reporting](#sector-aware-reporting)
- [Installation](#installation)
- [Usage](#usage)
- [Web Interface](#web-interface)
- [REST API & SIEM Export](#rest-api--siem-export)
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
├── SankofaEye_ghipss.com_20260527_113800.pdf                  ← branded intelligence report
├── SankofaEye_ghipss.com_20260527_113800_executive_summary.pdf ← board-ready summary (flows to 2 pages when warranted)
└── SankofaEye_ghipss.com_20260527_113800.json                 ← structured findings (machine-readable)
```

### Full Intelligence Report

| Section | Content |
|---------|---------|
| Cover & Risk Score | 0–100 score, severity rating, finding count, MITRE technique count |
| Executive Summary | Plain-English overview — suitable for IT management |
| Visualized Threat Killchain | Horizontal MITRE ATT&CK kill-chain flow diagram |
| Findings & Risk Analysis | Detail, recommendation, MITRE ATT&CK, full attack scenario narrative |
| Mobile Money Exposure | MoMo subdomain patterns, USSD/settlement/API/back-office, OPERA1ER scenarios |
| Regulatory Compliance | Sector-gated: BoG CISD / NCA Guidelines / DPC Act 843 — score (%) + control gaps |
| West Africa Threat Intelligence | Cross-referenced actors, historical incidents, IOC pattern matches |
| Inferred Attack Path | Reconstructed adversary kill-chain + crown-jewel risk verdict (Phase 5E) |
| Dark Web Persona Monitoring | Executive-name and brand-term hits in fraud context (Phase 5F) |
| Supplier / Third-Party Risk | Passive vendor posture + weakest-link + BoG CISD Section 6 hook (Phase 5G) |
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

### Executive Summary

Board-ready PDF for CISO and board. Plain English, no CVE numbers. Risk score, top findings, immediate actions. Flows onto a second page (Additional Findings) when a scan surfaces more than the top three.

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

**Ghana-specific & intelligence modules (unique to SankofaEye):**

| Module | What It Does |
|--------|-------------|
| MoMo Exposure | 30 Mobile Money subdomain patterns — USSD, settlement, back-office, auth, API. MTN MoMo, Telecel Cash, AirtelTigo Money. |
| Compliance Mapper | Maps every finding to BoG CISD, NCA Guidelines, and DPC Act 843 — sector-gated. Control ID, section reference, severity, remediation. |
| WA Threat DB | Cross-references scan profile against tracked West African threat actors with sector detection and IOC matching. |
| Attack Path | Reconstructs an inferred MITRE ATT&CK kill-chain from passive signals (Phase 5E). |
| Persona Monitor | Monitors dark web / fraud forums for executive names and brand terms (Phase 5F). |
| Supplier Risk | Lightweight passive vendor posture scoring + weakest-link + BoG CISD Section 6 (Phase 5G). |
| Threat Calendar | Surfaces time-sensitive seasonal risk (Q-end BEC, year-end, elections, salary windows) (Phase 5I). |
| Tech Fingerprint | URLScan-based tech stack detection (30+ patterns). CVE risk class mapping. |
| Email Scorecard | A–F grade on SPF / DKIM / DMARC. Weighted 0–100 score. |
| HTTP Security Headers | A–F grade on HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. **Non-intrusive active** — one direct GET to the target (see Ethical & Legal). Off by default. |
| Phishing Detector | Monitors crt.sh, WHOIS, and URLScan for lookalike domains targeting your brand. Pre-crime intelligence. |
| Benchmarking | Anonymised peer comparison — where does your score rank within your sector in Ghana? |
| Remediation Tracker | Tracks finding lifecycle: OPEN → IN_PROGRESS → RESOLVED → VERIFIED → REOPENED. Auto-verifies fixes. |

---

## Sector-Aware Reporting

SankofaEye classifies each target into one of six sectors and adapts the report accordingly. Sector is auto-detected from the domain (TLD + keywords) and can be overridden on the scan form.

| Sector | Regulated | Compliance Frameworks Shown | Framing |
|--------|-----------|------------------------------|---------|
| Government / Public Sector | Yes | DPC Act 843 | Public |
| Financial / Fintech | Yes | BoG CISD + DPC Act 843 | Public |
| Telecom / ISP | Yes | NCA Guidelines + DPC Act 843 | Public |
| Healthcare | Yes | DPC Act 843 (heightened) | Public |
| Education | Yes | DPC Act 843 | Public |
| Commercial / General | No | DPC Act 843 only | Commercial |

**DPC Act 843 applies to every organisation** that processes Ghanaian personal data, so it always appears. BoG CISD only shows for Financial; NCA only for Telecom. For non-regulated (commercial) targets, finding narratives are reframed from public-sector language ("citizens", "government domain") to commercial language ("customers", "brand domain") — so a media company is never assessed as a bank.

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

# Aegis-INT Natural Language Query (Enterprise / Professional feature)
ANTHROPIC_API_KEY=sk-ant-...

# Web interface
FLASK_SECRET_KEY=your_random_secret_key
# Optional — defaults to sankofaeye_web/instance/sankofaeye.db (absolute, CWD-safe)
# DATABASE_URL=sqlite:////absolute/path/to/sankofaeye.db

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
SMTP_USER=reports@afriwealthintel.com
SMTP_PASSWORD=your_app_password
APP_BASE_URL=https://yourdomain.com
```

| Key | Where to Get | Cost |
|-----|-------------|------|
| `CENSYS_API_TOKEN` | [search.censys.io](https://search.censys.io) → Account → API | Free |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | Free |
| `URLSCAN_API_KEY` | [urlscan.io/user/signup](https://urlscan.io/user/signup) | Free |
| `HIBP_API_KEY` | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) | ~$3.50/mo |
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | Usage-based |
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

# Access at http://localhost:5000
# Default admin: admin@afriwealthintel.com / SankofaEye2026!
```

> **macOS note:** Disable AirPlay Receiver in System Settings if port 5000 is in use,
> or kill it with `lsof -ti:5000 | xargs kill -9`, or change the port in `app.py`.

> **Database note:** the SQLite DB is anchored to an absolute path
> (`sankofaeye_web/instance/sankofaeye.db`) so it is identical regardless of which
> directory you launch from. If you change the User model schema, delete the DB and
> restart to rebuild, or run an `ALTER TABLE` migration.

### Scheduled Scans

```bash
# Run in a separate terminal alongside the Flask app
python scheduler/scan_scheduler.py
```

Schedules: Professional = weekly | Starter = monthly | Free = none (manual only).
Computes risk-score deltas between runs and sends email + WhatsApp + SMS when new findings are detected.

---

## Web Interface

| Feature | Details |
|---------|---------|
| Authentication | Register / login / logout with secure password hashing |
| Dashboard | Scan form (with sector selector) → recent scans → compliance → WA threat context → Ghana Threat Calendar → persona monitoring → MoMo exposure → supplier risk → plans |
| Scan Progress | Live polling every 3s, module checklist, real-time score reveal |
| Report Downloads | Full PDF, Executive PDF, raw JSON — per scan |
| Findings Viewer | In-browser findings table with severity badges, inferred attack path, and Aegis-INT NL query (Pro/Enterprise) |
| Compliance Widget | Sector-gated BoG / NCA / DPC scores with control gap list from last scan |
| WA Threat Intel | Threat actor cards — relevance, motivation, MITRE techniques |
| Ghana Threat Calendar | Colour-coded active seasonal threat windows (Phase 5I) |
| MoMo Exposure | Detected MoMo services and risk findings from last scan |
| Supplier Risk | Vendor posture + weakest link (Phase 5G) |
| Remediation Tracker | Track finding status (Open → In Progress → Resolved → Verified) per scan |
| Alert Settings | Configure Email, WhatsApp, SMS, and Webhook notification channels |
| API Settings | View / copy / regenerate API key, see usage and example calls (Phase 5J) |
| Peer Benchmarking | See how your score compares to sector peers in Ghana |
| Plans & Billing | Free / Starter / Professional / Enterprise with Paystack + Stripe |
| Scheduler | Automated scans, delta reports, multi-channel delivery |

---

## REST API & SIEM Export

Programmatic access for SOC automation and SIEM ingestion. Authenticate with an `X-API-Key` header (per-user key, found on the API Settings page). Rate limited per plan (Free 10/hr → Enterprise 3000/hr).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scan` | Submit a domain (optional `sector`) → returns `job_id` |
| GET | `/api/v1/scan/{job_id}` | Poll status; full results JSON when complete |
| GET | `/api/v1/export/splunk/{job_id}` | Findings as Splunk HEC events |
| GET | `/api/v1/export/elastic/{job_id}` | Findings as Elastic ECS documents |
| GET | `/api/v1/me` | Plan, usage, API key info |

Add `?ndjson=1` to either export endpoint for newline-delimited output (ready for Splunk HEC / Filebeat ingestion).

```bash
# Submit a scan
curl -X POST http://localhost:5000/api/v1/scan \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "sector": "financial"}'

# Export results to Splunk (newline-delimited)
curl "http://localhost:5000/api/v1/export/splunk/JOB_ID?ndjson=1" \
  -H "X-API-Key: YOUR_KEY"
```

---

## Project Structure

```
sankofaeye/
├── sankofaeye.py                        # Main CLI orchestrator
├── config.yaml                          # Module toggles, risk weights, brand, personas, suppliers
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
│   ├── compliance_mapper.py             # Sector-gated BoG / NCA / DPC mapping
│   ├── sector.py                        # Sector taxonomy, detection, framing (NEW)
│   ├── attack_path.py                   # Inferred kill-chain reconstruction (Phase 5E)
│   ├── supplier_risk.py                 # Third-party vendor risk scoring (Phase 5G)
│   ├── threat_calendar.py               # Ghana seasonal threat context (Phase 5I)
│   ├── tech_fingerprint.py              # Technology stack detection + CVE mapping
│   ├── email_scorer.py                  # A–F Email Security Scorecard
│   ├── headers_scorer.py                # A–F HTTP Security Headers (non-intrusive active)
│   ├── benchmarking.py                  # Anonymised peer sector benchmarking
│   ├── remediation_tracker.py           # Finding lifecycle tracking + auto-verification
│   ├── logger.py                        # Coloured console + file logging
│   └── validator.py                     # Domain input validation
│
├── reports/
│   ├── pdf_generator.py                 # Full branded report (sector-aware)
│   └── executive_onepager.py            # Board-ready executive summary PDF (sector-aware)
│
├── intel/
│   ├── wa_threatdb.json                 # West Africa threat actor database
│   ├── wa_threatdb_module.py            # Threat DB cross-reference engine
│   ├── threat_calendar.json             # Ghana threat calendar data (Phase 5I)
│   └── benchmark_db.json                # Anonymised sector benchmark scores (auto-built)
│
├── monitoring/
│   ├── __init__.py
│   ├── phishing_detector.py             # crt.sh + WHOIS + URLScan lookalike monitoring
│   └── persona_monitor.py               # Dark web persona / brand monitoring (Phase 5F)
│
├── alerts/
│   ├── __init__.py
│   └── alert_engine.py                  # Email + WhatsApp + SMS + Webhook dispatcher
│
├── scheduler/
│   └── scan_scheduler.py                # Recurring scans + delta reports + delivery
│
├── sankofaeye_web/                      # Flask web application
│   ├── app.py                           # Application factory, models, blueprints
│   ├── routes/
│   │   ├── auth.py                      # Login, register, logout
│   │   ├── scan.py                      # Dashboard, scan submission, progress polling
│   │   ├── reports.py                   # Report listing and downloads
│   │   ├── billing.py                   # Paystack + Stripe payment integration
│   │   ├── tracker.py                   # Remediation tracker + alert settings
│   │   ├── intelligence.py              # Aegis-INT NL query (Phase 5H)
│   │   └── api.py                       # REST API + SIEM export (Phase 5J)
│   └── templates/
│       ├── base.html                    # AfriWealth CI branded base layout
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html               # Main dashboard with all intelligence widgets
│       ├── scan_progress.html           # Live scan progress with module checklist
│       ├── reports.html                 # Report listing
│       ├── findings.html                # Findings viewer + attack path + NL query
│       ├── attack_path_widget.html      # Kill-chain widget (Phase 5E)
│       ├── tracker.html                 # Remediation tracker view
│       ├── alert_settings.html          # Alert channel configuration
│       ├── api_settings.html            # API key management (Phase 5J)
│       └── error.html
│
├── output/                              # Generated reports — gitignored
├── logs/                                # Scan logs — gitignored
└── samples/                             # Redacted example report
```

---

## Configuration

`config.yaml` controls module settings, brand, output, alert recipients, personas, and suppliers:

```yaml
brand:
  tool:     SankofaEye
  version:  1.0.0
  name:     AfriWealth Cyber Intelligence
  analyst:  DeCyberGuardian
  website:  https://afriwealthintel.com

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
  theharvester: 120
  shodan:       30
  hibp:         20
  virustotal:   30
  darkweb:      45
  hudsonrock:   30
  dns:          30
  ssl:          45

output:
  directory:       output
  log_directory:   logs
  pdf_report:      true
  json_dump:       true
  log_level:       INFO

# Phase 5F — Dark Web Persona Monitoring
personas:
  executives:
    - name: "John Mensah"
      title: "CEO"
      email_pattern: "jmensah"
  brand_terms: ["afriwealth", "sankofaeye"]

# Phase 5G — Supplier / Third-Party Risk
suppliers:
  - domain: "vendor-example.com"
    name: "Core Banking Provider"
    criticality: high

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
| **Free** | $0 | 1/mo | Full PDF report, executive summary, all 10 modules |
| **Starter** | $49/mo | 5/mo | Monthly scheduling, email + WhatsApp delivery, delta reports |
| **Professional** | $149/mo | 20/mo | Weekly scans, WA threat context, sector-gated compliance, peer benchmarking, NL query |
| **Enterprise** | $499/mo | Unlimited | Aegis-INT DRIB briefs, REST API + SIEM export, dedicated analyst support, custom regulatory mapping |

Payment via **Paystack** (MTN MoMo, Telecel Cash, AirtelTigo Money, card, bank transfer) and **Stripe** (international card).

---

## Ethical & Legal Guidelines

> **Authorised use only.**

SankofaEye is **passive-first**: with one clearly-labelled exception, it gathers everything from third-party OSINT sources and never contacts the target directly.

**The one exception — HTTP Security Headers (non-intrusive active).** When enabled (`modules.security_headers`, off by default), this single module makes one ordinary HTTP GET to the target's web server to read the security headers it returns to every visitor. This is the same request any browser makes — no authentication, no payloads, no vulnerability testing — but unlike the passive modules it *will* appear in the target's access logs. Every report that includes it discloses this in the section text, so the one direct request is never hidden. Leave it disabled for unsolicited/prospecting scans; enable it only for domains you own or are authorised to assess.

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
- [x] Branded PDF report + executive summary
- [x] Email Security Scorecard (A–F)
- [x] Technology fingerprinting + CVE class mapping
- [x] Mobile Money exposure module (30 patterns — MTN MoMo / Telecel / AirtelTigo)
- [x] Regulatory compliance mapper (BoG CISD / NCA / DPC Act 843)
- [x] West Africa Threat Intelligence database
- [x] `--report-only` mode
- [x] Flask web interface — multi-user, plans, billing
- [x] Paystack integration (Ghana-first: MTN MoMo, card, bank transfer)
- [x] Stripe integration skeleton (international)
- [x] Scheduled recurring scans + delta reports + email delivery
- [x] 4-tier pricing: Free / Starter / Professional / Enterprise (Aegis-INT)
- [x] Phishing infrastructure detection (crt.sh + WHOIS + URLScan)
- [x] Multi-channel alerts: Email + WhatsApp + SMS + Webhook (Slack/Teams)
- [x] Peer benchmarking (anonymised sector score comparison)
- [x] Remediation tracker (OPEN → IN_PROGRESS → RESOLVED → VERIFIED → REOPENED)
- [x] **Phase 5E — Inferred attack path (Ghana-specific MITRE kill-chain per scan)**
- [x] **Phase 5F — Dark web persona monitoring (executive names + brand terms)**
- [x] **Phase 5G — Supplier / third-party risk scoring + BoG CISD Section 6 hook**
- [x] **Phase 5H — Natural language query (Aegis-INT bridge, Pro/Enterprise)**
- [x] **Phase 5I — Ghana Threat Calendar (elections, quarter-end, national events)**
- [x] **Phase 5J — REST API (`/api/v1/scan`) + SIEM export (Splunk HEC / Elastic ECS)**
- [x] **Sector-aware reporting (6 sectors, auto-detect + override, framework gating)**
- [x] **HTTP Security Headers scorecard (A–F; non-intrusive active, opt-in)**
- [x] **Sector-aware WA threat-actor selection (commercial targets exclude bank/gov-only actors)**

**In Progress 🔄**
- [ ] Aegis-INT DRIB integration (Enterprise — decision-ready intelligence briefs)
- [ ] Paystack live account + Stripe activation
- [ ] Hostinger company email migration
- [ ] Obsidian vault export (scan findings as structured markdown notes)

**Planned 📋**
- [ ] Continuous monitoring mode (diff alerts between scheduled runs)
- [ ] Multi-domain portfolio view for client management
- [ ] Historical trend dashboards (risk-score-over-time per domain)
- [ ] WhatsApp report delivery (full PDF via WhatsApp)
- [ ] Mobile app (React Native)

---

## Author

**Stephen Oppong (DeCyberGuardian)**
Founder & Lead Analyst — AfriWealth Cyber Intelligence
Cyber Threat Intelligence Practitioner | Accra, Ghana

[![LinkedIn](https://img.shields.io/badge/LinkedIn-DeCyberGuardian-008080?style=flat-square&logo=linkedin)](https://linkedin.com/in/decyberguardian)
[![X](https://img.shields.io/badge/X-@DeCyberGuardian-FFD700?style=flat-square&logo=x)](https://x.com/decyberguardian)
[![Website](https://img.shields.io/badge/Website-afriwealthintel.com-008080?style=flat-square)](https://afriwealthintel.com)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with 🔍 in Ghana for the African digital ecosystem.*  
*Passive reconnaissance only. No active exploitation was performed in the making of this platform.*