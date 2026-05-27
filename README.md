# SankofahEye 👁️
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

SankofahEye is a **passive exposure intelligence platform** built for cyber threat intelligence practitioners operating in Ghana and the broader West African digital ecosystem.

It chains 10 open-source intelligence modules to produce a structured **Exposure Intelligence Report** — branded, PDF-formatted, with MITRE ATT&CK mappings, West Africa threat actor context, mobile money exposure analysis, and regulatory compliance mapping to BoG CISD, NCA Guidelines, and DPC Act 843.

Available as a **CLI tool** and a **Flask web application** with multi-user support, scan scheduling, and tiered plans (Free → Starter → Professional → Enterprise).

**No active exploitation. No direct target interaction. Pure passive OSINT.**

---

## Contents

- [What SankofahEye Produces](#what-sankofaeye-produces)
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

## What SankofahEye Produces

Every scan generates two files — a full intelligence report and a raw data export:

```
output/
├── SankofahEye_ghipss.com_20260527_113800.pdf    ← 14-page branded intelligence report
├── SankofahEye_ghipss.com_20260527_113800_executive_summary.pdf  ← Board-ready one-pager
└── SankofahEye_ghipss.com_20260527_113800.json   ← Structured findings (machine-readable)
```

### Full Intelligence Report (14 pages)

| Section | Content |
|---------|---------|
| Cover & Risk Score | 0–100 score, severity rating (Low / Medium / High / Critical), finding count, MITRE technique count |
| Executive Summary | Plain-English overview of exposure — suitable for IT management |
| Findings & Risk Analysis | Each finding: detail, recommendation, MITRE ATT&CK technique, full attack scenario narrative |
| Mobile Money Exposure | MoMo subdomain patterns, USSD/settlement/API/back-office exposure, OPERA1ER attack scenarios |
| Regulatory Compliance | BoG CISD / NCA Guidelines / DPC Act 843 — score (%) + specific control gaps with section references |
| West Africa Threat Intelligence | Cross-referenced threat actors, historical incident context, IOC pattern matches |
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

A single-page PDF for CISO and board audiences. Plain English, no CVE numbers. Risk score, top findings, immediate actions, AfriWealth CI branding.

---

## Intelligence Modules

| # | Module | Source | Data Collected | API Key |
|---|--------|--------|----------------|---------|
| 1 | Subfinder | ProjectDiscovery | Subdomains via cert transparency, DNS datasets, brute-force | No |
| 2 | theHarvester | Laramies | Emails, hostnames, IPs from search engines and DNS | No |
| 3 | Censys | Censys.io | Exposed ports, services, banners, CVEs | Yes (free) |
| 4 | HIBP | HaveIBeenPwned | Breached email accounts by domain | Yes (paid ~$3.50/mo) |
| 5 | VirusTotal | VirusTotal | Domain reputation, malicious votes, flagged vendors | Yes (free) |
| 6 | URLScan.io | URLScan | Passive web scans, technology fingerprinting, screenshots | Yes (free) |
| 7 | HudsonRock | Cavalier API | Infostealer / malware log credential exposure | No |
| 8 | Dark Web | Ahmia.fi | Dark web indexed mentions of the target domain | No |
| 9 | DNS Security | dnspython | SPF, DMARC, DKIM, MX, NS records — full email auth analysis | No |
| 10 | SSL/TLS | ssl / requests | Certificate validity, expiry, weak protocol detection | No |

**Ghana-specific modules (unique to SankofahEye):**

| Module | What It Does |
|--------|-------------|
| MoMo Exposure | 30 Mobile Money subdomain patterns — USSD, settlement, back-office, auth, API endpoints. MTN MoMo, Telecel Cash, AirtelTigo Money. OPERA1ER attack scenarios. |
| Compliance Mapper | Maps every finding to BoG CISD, NCA Guidelines, and DPC Act 843. Control ID, section reference, severity, remediation. |
| WA Threat DB | Cross-references scan profile against 6 tracked West African threat actors. Sector detection, IOC pattern matching, historical incident context. |
| Tech Fingerprint | URLScan-based tech stack detection (30+ patterns). CVE risk class mapping for WordPress, Zimbra, cPanel, ASP.NET, etc. |
| Email Scorecard | A–F grade on SPF / DKIM / DMARC. Weighted 0–100 score. Specific misconfiguration detail per control. |

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
# Required for full functionality
CENSYS_API_TOKEN=your_censys_personal_access_token
CENSYS_ORG_ID=your_censys_organization_id
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLSCAN_API_KEY=your_urlscan_api_key

# Optional — enables credential exposure module
HIBP_API_KEY=your_hibp_api_key

# Web interface
FLASK_SECRET_KEY=your_random_secret_key
DATABASE_URL=sqlite:///sankofaeye.db

# Payment (Paystack — Ghana-first: MoMo, card, bank transfer)
PAYSTACK_SECRET_KEY=sk_live_...
PAYSTACK_PUBLIC_KEY=pk_live_...

# Payment (Stripe — optional, international)
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
python sankofaeye.py --report-only output/SankofahEye_ghipss.com_20260527.json

# Custom config file
python sankofaeye.py --domain example.com --config config.yaml
```

### Web Interface

```bash
# Run from the sankofaeye/ root directory
python sankofaeye_web/app.py

# Access at http://localhost:8080
# Default admin: admin@afriwealthci.com / SankofahEye2026!
```

> **Note:** Always run from the `sankofaeye/` root, not from inside `sankofaeye_web/`.  
> macOS users: disable AirPlay Receiver in System Settings if port 5000 is in use, or change port to 8080 in `app.py`.

### Scheduled Scans

Run alongside the Flask app to enable automatic recurring scans with delta reports and email delivery:

```bash
# In a separate terminal
python scheduler/scan_scheduler.py
```

Schedules: Enterprise = daily | Professional = weekly | Starter = monthly.  
Sends email with PDF attachments when new findings are detected.

---

## Web Interface

The Flask web application provides a full multi-user platform:

| Feature | Details |
|---------|---------|
| Authentication | Register / login / logout with secure password hashing |
| Dashboard | Scan form → recent results → compliance status → WA threat context → MoMo exposure → plans |
| Scan Progress | Live polling every 3 seconds, module checklist, real-time score reveal |
| Report Downloads | Full PDF, Executive PDF, raw JSON — per scan |
| Findings Viewer | In-browser findings table with severity badges and stats |
| Compliance Widget | BoG / NCA / DPC scores with control gap list from last scan |
| WA Threat Intel | Threat actor cards from last scan — relevance, motivation, MITRE techniques |
| MoMo Exposure | Detected MoMo services and risk findings from last scan |
| Plans | Free / Starter / Professional / Enterprise with Paystack + Stripe checkout |
| Billing | Paystack (MTN MoMo, Telecel, AirtelTigo, card, bank transfer) + Stripe |
| Scheduler | Automated scans, delta reports, email delivery |

**Dashboard layout — value before commercial:**
```
1. Scan form
2. Recent scans + PDF downloads
3. Regulatory compliance (BoG / NCA / DPC) — after first scan
4. West Africa threat intel context
5. Mobile money exposure
6. Plans (last — value demonstrated first)
```

---

## Project Structure

```
sankofaeye/
├── sankofaeye.py                      # Main CLI orchestrator
├── config.yaml                        # Module toggles, risk weights, brand config
├── requirements.txt                   # Python dependencies
├── .env.example                       # API key + config template
├── .gitignore
│
├── modules/
│   ├── subfinder_module.py            # Subdomain enumeration
│   ├── harvester_module.py            # Email + host harvesting
│   ├── censys_module.py               # Exposed services (Censys API)
│   ├── hibp_module.py                 # Credential leak check (HIBP)
│   ├── vt_urlscan_module.py           # Domain reputation + tech fingerprint
│   ├── darkweb_module.py              # Dark web mention search (Ahmia)
│   ├── hudsonrock_module.py           # Infostealer credential exposure
│   ├── dns_module.py                  # DNS + email security analysis
│   └── momo_module.py                 # Mobile Money exposure (Ghana-specific)
│
├── utils/
│   ├── aggregator.py                  # Normalise + merge all module findings
│   ├── risk_scorer.py                 # Risk scoring + MITRE ATT&CK mapping
│   ├── compliance_mapper.py           # BoG CISD / NCA / DPC Act 843 mapping
│   ├── tech_fingerprint.py            # Technology stack detection + CVE mapping
│   ├── email_scorer.py                # A–F Email Security Scorecard
│   ├── logger.py                      # Coloured console + file logging
│   └── validator.py                   # Domain input validation
│
├── reports/
│   ├── pdf_generator.py               # Full 14-page AfriWealth CI branded report
│   └── executive_onepager.py          # Board-ready executive summary PDF
│
├── intel/
│   ├── wa_threatdb.json               # West Africa threat actor database
│   └── wa_threatdb_module.py          # Threat DB cross-reference engine
│
├── scheduler/
│   └── scan_scheduler.py              # Recurring scans + delta reports + email
│
├── sankofaeye_web/                    # Flask web application
│   ├── app.py                         # Application factory, models, blueprints
│   ├── routes/
│   │   ├── auth.py                    # Login, register, logout
│   │   ├── scan.py                    # Dashboard, scan submission, progress polling
│   │   ├── reports.py                 # Report listing and downloads
│   │   └── billing.py                 # Paystack + Stripe payment integration
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       ├── scan_progress.html
│       ├── reports.html
│       ├── findings.html
│       └── error.html
│
├── output/                            # Generated reports — gitignored
├── logs/                              # Scan logs — gitignored
└── samples/                           # Redacted example report
```

---

## Configuration

`config.yaml` controls all module settings, brand, and output:

```yaml
brand:
  tool:     SankofahEye
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
```

---

## Plans & Pricing

| Plan | Price | Scans | Key Features |
|------|-------|-------|-------------|
| **Free** | $0 | 1/mo | Full PDF report, executive one-pager, all 10 modules |
| **Starter** | $49/mo | 5/mo | Monthly scheduling, email delivery, delta reports |
| **Professional** | $149/mo | 20/mo | Weekly scans, WA threat context, BoG/NCA/DPC mapping |
| **Enterprise** | $499/mo | Unlimited | Aegis-INT DRIB briefs, dedicated analyst support, custom regulatory mapping |

Payment via **Paystack** (MTN MoMo, Telecel Cash, AirtelTigo Money, card, bank transfer) and **Stripe** (international card).

---

## Ethical & Legal Guidelines

> **Authorised use only.**

SankofahEye is a passive reconnaissance tool. It collects intelligence exclusively from public sources and third-party APIs — no packets are sent to the target domain, no systems are probed or touched.

- Only scan domains you **own** or have **explicit written authorisation** to assess
- Handle credential data and report outputs with strict access controls — reports are **CONFIDENTIAL**
- Comply with Ghana's **Data Protection Act 2012 (Act 843)** when processing or storing personal data found in breach results
- Respect all API provider terms of service and rate limits
- SankofahEye findings are intelligence, not legal advice — engage a qualified compliance officer for formal regulatory assessments

---

## Roadmap

**Completed ✅**
- [x] 10-module passive OSINT pipeline
- [x] Risk scoring engine + MITRE ATT&CK mapping
- [x] Branded 14-page PDF report + executive one-pager
- [x] Email Security Scorecard (A–F)
- [x] Technology fingerprinting + CVE class mapping
- [x] Mobile Money exposure module (MTN MoMo / Telecel / AirtelTigo)
- [x] Regulatory compliance mapper (BoG CISD / NCA / DPC Act 843)
- [x] West Africa Threat Intelligence database (6 actors + incident history)
- [x] `--report-only` mode
- [x] Flask web interface — multi-user, plans, billing
- [x] Paystack integration (Ghana-first payments)
- [x] Stripe integration skeleton (international)
- [x] Scheduled recurring scans + delta reports + email delivery
- [x] 4-tier pricing with Enterprise plan

**In Progress 🔄**
- [ ] Aegis-INT DRIB integration (Enterprise tier — decision-ready intelligence briefs)
- [ ] Paystack live keys + Stripe account activation
- [ ] Company email setup (Hostinger migration)

**Planned 📋**
- [ ] REST API (`/api/v1/scan`) for programmatic access
- [ ] DNS monitoring alerts (notify on new subdomain creation)
- [ ] Certificate transparency monitoring (crt.sh integration)
- [ ] Multi-domain portfolio view for client management
- [ ] SIEM integration (Splunk / Elastic export)
- [ ] WhatsApp report delivery (Ghana-relevant channel)
- [ ] Mobile app (React Native — for on-the-go scan results)

---

## Author

**Stephen Oppong** **DeCyberGuardian**
Founder & Lead Analyst — AfriWealth Cyber Intelligence
Cyber Threat Intelligence Practitioner | Ghana

[![LinkedIn](https://img.shields.io/badge/LinkedIn-DeCyberGuardian-008080?style=flat-square&logo=linkedin)](https://linkedin.com/in/decyberguardian)
[![X](https://img.shields.io/badge/X-@DeCyberGuardian-FFD700?style=flat-square&logo=x)](https://x.com/decyberguardian)
[![Website](https://img.shields.io/badge/Website-afriwealthci.com-008080?style=flat-square)](https://afriwealthci.com)

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

*Built with 🔍 in Ghana for the African digital ecosystem.*
*Passive reconnaissance only. No active exploitation was performed in the making of this platform.*
