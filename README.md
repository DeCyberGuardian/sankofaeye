# SankofahEye 👁️
### Passive Exposure Intelligence Platform
**By AfriWealth Cyber Intelligence**

[![Python](https://img.shields.io/badge/Python-3.12+-008080?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-FFD700?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-008080?style=flat-square)](https://github.com)
[![Status](https://img.shields.io/badge/Status-Active-FFD700?style=flat-square)](https://github.com)

> *"Go back and fetch it."* — Sankofa proverb. Look back at what is exposed before an adversary does.

SankofahEye is a passive reconnaissance and digital exposure scanning platform built for 
cyber threat intelligence practitioners operating in Ghana and the broader West African 
digital ecosystem. It chains multiple open-source intelligence sources to produce a 
structured, branded **Exposure Intelligence Report** in PDF format — with attack scenario 
narratives, MITRE ATT&CK mappings, and actionable remediation guidance.

**No active exploitation. No direct target interaction. Pure passive OSINT.**

---

## 📸 Sample Report

![SankofahEye Report Cover](samples/report_preview.png)

> See [`samples/`](samples/) for a redacted example report.

---

## 🔍 Intelligence Sources

| Module | Source | Data Collected | API Key Required |
|--------|--------|----------------|-----------------|
| Subfinder | ProjectDiscovery | Subdomains via cert transparency, DNS datasets | No |
| theHarvester | Laramies | Emails, hostnames, IPs | No |
| Censys | Censys.io | Exposed ports, services, banners | Yes (free tier) |
| HIBP | HaveIBeenPwned | Breached email accounts | Yes (paid) |
| VirusTotal | VirusTotal | Domain reputation, malware flags | Yes (free tier) |
| URLScan.io | URLScan | Passive web scans, technologies | Yes (free tier) |
| HudsonRock | Cavalier API | Infostealer / malware log exposure | No |
| Dark Web | Ahmia.fi | Dark web indexed mentions | No |
| DNS | dnspython | SPF, DMARC, DKIM, MX, NS analysis | No |

---

## 📊 Report Output

Each scan generates a branded **AfriWealth Cyber Intelligence Exposure Report** containing:

- Executive summary with risk score (0–100) and severity rating
- Findings & risk analysis with **attack scenario narratives**
- Subdomain inventory
- Exposed services (ports, CVEs, banners)
- Credential exposure (breach databases)
- Dark web monitoring results
- DNS & email security analysis (SPF, DMARC, DKIM)
- MITRE ATT&CK technique mapping table
- Infostealer exposure (HudsonRock Cavalier)

---

## ⚙️ Installation

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
# macOS (recommended)
brew install subfinder

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

Open `.env` and add your keys:

```env
CENSYS_API_TOKEN=your_censys_personal_access_token 
CENSYS_ORG_ID=your_censys_organization_id
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLSCAN_API_KEY=your_urlscan_api_key
HIBP_API_KEY=your_hibp_api_key  # optional — paid plan 
```

| Key | Where to Get | Cost |
|-----|-------------|------|
| `CENSYS_API_TOKEN` | [search.censys.io](https://search.censys.io) | Free |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | Free |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/signup) | Free |
| `HIBP_API_KEY` | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) | ~$3.50/mo |

---

## 🚀 Usage

```bash
# Activate virtual environment first
source venv/bin/activate

# Scan a single domain
python sankofaeye.py --domain example.com

# Scan multiple domains
python sankofaeye.py --domain gcb.com.gh mtn.com.gh bog.gov.gh --output ./output

# Custom output directory
python sankofaeye.py --domain example.com --output ./reports

# Custom config file
python sankofaeye.py --domain example.com --config config.yaml
```

### Output

Each scan produces two files in your output directory:

output/
├── SankofahEye_example.com_20260525_120000.pdf   ← Branded exposure report
└── SankofahEye_example.com_20260525_120000.json  ← Raw findings data

---

## 🗂️ Project Structure
sankofaeye/
├── sankofaeye.py              # Main orchestrator — CLI entry point
├── config.yaml                # Module toggles, risk weights, brand settings
├── requirements.txt           # Python dependencies
├── .env.example               # API key template
├── .gitignore                 # Excludes .env, output/, logs/
│
├── modules/
│   ├── subfinder_module.py    # Subdomain enumeration
│   ├── harvester_module.py    # Email + host harvesting
│   ├── censys_module.py       # Exposed services (Censys API)
│   ├── hibp_module.py         # Credential leak check
│   ├── vt_urlscan_module.py   # Domain reputation
│   ├── darkweb_module.py      # Dark web mention search
│   ├── hudsonrock_module.py   # Infostealer log check
│   └── dns_module.py          # DNS security analysis
│
├── utils/
│   ├── aggregator.py          # Normalise + merge all findings
│   ├── risk_scorer.py         # Risk score + MITRE ATT&CK mapping
│   ├── logger.py              # Coloured console + file logging
│   └── validator.py           # Domain input validation
│
├── reports/
│   └── pdf_generator.py       # AfriWealth branded PDF report
│
├── output/                    # Generated reports (gitignored)
├── logs/                      # Scan logs (gitignored)
└── samples/                   # Redacted example report

---

## 🛡️ Ethical & Legal Guidelines

> **Authorised use only.**

- Only scan domains you **own** or have **explicit written authorisation** to assess
- SankofahEye performs **passive reconnaissance only** — no active exploitation, no direct probing of target systems
- All intelligence is gathered from public sources and third-party APIs
- Handle credential data and report outputs with strict access controls
- Comply with Ghana's **Data Protection Act 2012 (Act 843)** when processing personal data
- Respect all API provider terms of service and rate limits
- Reports are **CONFIDENTIAL** — distribute only to authorised personnel

---

## 🗺️ Roadmap

- [ ] SSL/TLS certificate expiry and validity checking
- [ ] `--report-only` mode to regenerate PDF from existing JSON
- [ ] Web interface (Flask + React dashboard)
- [ ] DNS monitoring alerts (notify on new subdomain discovery)
- [ ] Certificate transparency monitoring (crt.sh integration)
- [ ] Scheduled recurring scans with delta reports
- [ ] Ghana/West Africa threat actor profile database
- [ ] Multi-target portfolio scanning for client management

---

## 👤 Author

**DeCyberGuardian**  
Cyber Threat Intelligence Practitioner  
AfriWealth Cyber Intelligence | Ghana  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-DeCyberGuardian-008080?style=flat-square&logo=linkedin)](https://linkedin.com/in/decyberguardian)
[![X](https://img.shields.io/badge/X-@DeCyberGuardian-FFD700?style=flat-square&logo=x)](https://x.com/decyberguardian)

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

*Built with 🔍 in Ghana for the African digital ecosystem.*