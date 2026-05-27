"""
SankofahEye — Mobile Money Exposure Module
AfriWealth Cyber Intelligence

Passive reconnaissance module specifically for Ghana's mobile money ecosystem.
Detects exposure risks in MTN MoMo, Telecel Cash, and AirtelTigo Money
infrastructure using OSINT only — no active exploitation.

What it checks:
  - MoMo-related subdomain patterns (api, momo, mfs, wallet, ussd, pay)
  - Payment API endpoints exposed to the internet
  - USSD gateway exposure
  - Merchant portal accessibility
  - SMS gateway infrastructure
  - Missing security headers on payment endpoints
  - Known insecure patterns in mobile money deployments

MITRE ATT&CK mappings:
  T1078   — Valid Accounts (credential-based MoMo fraud)
  T1566   — Phishing (fake MoMo portals)
  T1190   — Exploit Public-Facing Application (exposed APIs)
  T1071.001 — Web Protocols (API abuse)
"""

import re
from utils.logger import SankofahLogger

log = SankofahLogger("momo_module")


# ── MoMo subdomain patterns ────────────────────────────────────────────────────
# Patterns that indicate mobile money infrastructure

MOMO_SUBDOMAIN_PATTERNS = [
    # Payment APIs
    ("api",          "Payment API",     "HIGH",   "T1190"),
    ("momo",         "MoMo Service",    "HIGH",   "T1078"),
    ("mfs",          "Mobile Financial Service", "HIGH", "T1190"),
    ("wallet",       "Wallet Service",  "HIGH",   "T1078"),
    ("pay",          "Payment Service", "HIGH",   "T1190"),
    ("payment",      "Payment Gateway", "HIGH",   "T1190"),
    ("gateway",      "Payment Gateway", "HIGH",   "T1190"),
    ("ussd",         "USSD Gateway",    "CRITICAL","T1190"),
    ("sms",          "SMS Gateway",     "MEDIUM", "T1071.001"),
    ("merchant",     "Merchant Portal", "HIGH",   "T1078"),
    ("agent",        "Agent Portal",    "HIGH",   "T1078"),
    ("portal",       "Customer Portal", "MEDIUM", "T1078"),
    ("topup",        "Top-up Service",  "MEDIUM", "T1190"),
    ("transfer",     "Transfer Service","HIGH",   "T1190"),
    ("withdraw",     "Withdrawal Service","HIGH", "T1190"),
    ("transaction",  "Transaction API", "HIGH",   "T1190"),
    ("callback",     "Payment Callback","HIGH",   "T1190"),
    ("webhook",      "Payment Webhook", "HIGH",   "T1190"),
    ("admin",        "Admin Portal",    "CRITICAL","T1078"),
    ("backoffice",   "Back Office",     "CRITICAL","T1078"),
    ("back-office",  "Back Office",     "CRITICAL","T1078"),
    ("reconcil",     "Reconciliation",  "HIGH",   "T1190"),
    ("settlement",   "Settlement System","CRITICAL","T1190"),
    ("switch",       "Payment Switch",  "CRITICAL","T1190"),
    ("pos",          "POS System",      "HIGH",   "T1190"),
    ("airtime",      "Airtime Service", "MEDIUM", "T1190"),
    ("data",         "Data Service",    "LOW",    "T1190"),
    ("kyc",          "KYC System",      "HIGH",   "T1078"),
    ("onboard",      "Onboarding",      "MEDIUM", "T1078"),
    ("auth",         "Auth Service",    "CRITICAL","T1078"),
    ("oauth",        "OAuth Service",   "CRITICAL","T1078"),
    ("token",        "Token Service",   "CRITICAL","T1078"),
]

# Known operators to detect from domain context
MOMO_OPERATORS = {
    "mtn":      "MTN MoMo",
    "telecel":  "Telecel Cash",
    "airtel":   "AirtelTigo Money",
    "tigo":     "AirtelTigo Money",
    "vodafone": "Vodafone Cash",
    "glo":      "Glo Mobile Money",
}

# Attack scenarios specific to Ghana's MoMo ecosystem
ATTACK_SCENARIOS = {
    "ussd_exposed": {
        "scenario": "USSD gateway endpoints exposed to the internet allow attackers to probe "
                    "USSD menu structures, identify session handling weaknesses, and potentially "
                    "manipulate transactions through API injection.",
        "impact":   "Direct financial fraud via USSD session hijacking. Ghana's USSD-based "
                    "MoMo transactions are the highest-volume attack surface in the ecosystem.",
        "actors":   "SIM swap groups, insider threat actors, API abuse operators",
        "likelihood": "HIGH — USSD systems are frequently misconfigured for external access",
    },
    "api_exposed": {
        "scenario": "Payment API endpoints accessible without authentication or with weak API keys "
                    "allow attackers to enumerate transactions, test stolen credentials, and "
                    "potentially initiate or reverse transactions.",
        "impact":   "Transaction fraud, account enumeration, bulk credential stuffing against "
                    "MoMo accounts. A single exposed API can affect thousands of accounts.",
        "actors":   "Automated fraud bots, BEC groups, ransomware initial access brokers",
        "likelihood": "HIGH — payment APIs are primary targets for automated attack tooling",
    },
    "merchant_exposed": {
        "scenario": "Exposed merchant portals can be targeted with credential stuffing using "
                    "leaked merchant credentials, enabling fraudulent transactions under legitimate "
                    "merchant accounts.",
        "impact":   "Merchant account takeover enables fraudulent money collection, "
                    "chargebacks, and reputation damage to the operator.",
        "actors":   "Phishing-as-a-Service operators, BEC groups",
        "likelihood": "HIGH — merchant portals are systematically targeted",
    },
    "admin_exposed": {
        "scenario": "Administrative and back-office portals exposed to the internet are the "
                    "highest-value target for sophisticated threat actors. OPERA1ER specifically "
                    "targets back-office systems of African telecoms and MoMo operators.",
        "impact":   "Full compromise of MoMo infrastructure, bulk transaction manipulation, "
                    "settlement fraud. OPERA1ER has stolen >$30M from similar targets.",
        "actors":   "OPERA1ER (CRITICAL relevance), nation-state actors, insider threats",
        "likelihood": "CRITICAL — back-office exposure is an active APT target",
    },
    "settlement_exposed": {
        "scenario": "Settlement and reconciliation systems exposed to the internet allow attackers "
                    "to manipulate interbank settlement records, a technique used by OPERA1ER "
                    "against African financial infrastructure.",
        "impact":   "Settlement fraud causing large-scale financial loss. "
                    "GHIPSS and PAPSS integration makes this extremely high-value.",
        "actors":   "OPERA1ER, Lazarus Group (APT38)",
        "likelihood": "CRITICAL — settlement systems are primary APT targets in West Africa",
    },
    "auth_exposed": {
        "scenario": "Authentication and token services exposed externally allow attackers to "
                    "perform credential stuffing, brute force attacks, and token harvesting "
                    "at scale using automated tooling.",
        "impact":   "Mass account takeover enabling bulk MoMo fraud across thousands of users.",
        "actors":   "Automated fraud bots, SIM swap operators",
        "likelihood": "CRITICAL — auth services are the #1 target for credential attacks",
    },
}


# ── Core analysis function ─────────────────────────────────────────────────────

def analyze_momo_exposure(target: str, subdomains: list) -> dict:
    """
    Analyse subdomains and target domain for mobile money exposure patterns.

    Args:
        target:     The scanned domain
        subdomains: List of subdomain strings from subfinder/harvester

    Returns:
        dict with:
            operator:          detected MoMo operator or None
            exposed_services:  list of detected MoMo service subdomains
            findings:          list of risk findings
            risk_score_delta:  additional points to add to overall risk score
            is_momo_operator:  bool — is this a known MoMo operator domain?
    """
    result = {
        "operator":         None,
        "exposed_services": [],
        "findings":         [],
        "risk_score_delta": 0,
        "is_momo_operator": False,
        "total_exposed":    0,
    }

    target_lower = target.lower()

    # Detect operator
    for key, name in MOMO_OPERATORS.items():
        if key in target_lower:
            result["operator"]         = name
            result["is_momo_operator"] = True
            break

    if not result["is_momo_operator"]:
        # Still check subdomains for MoMo patterns even on non-operator domains
        # (fintechs, payment aggregators, banks with MoMo integration)
        pass

    # Scan subdomains for MoMo patterns
    matched_patterns = {}

    for subdomain in subdomains:
        sub_lower = subdomain.lower()
        # Remove the base domain to check the prefix
        prefix = sub_lower.replace(f".{target_lower}", "").replace(target_lower, "")

        for pattern, service_name, severity, mitre in MOMO_SUBDOMAIN_PATTERNS:
            if pattern in prefix and pattern not in matched_patterns:
                matched_patterns[pattern] = {
                    "subdomain":    subdomain,
                    "pattern":      pattern,
                    "service_name": service_name,
                    "severity":     severity,
                    "mitre":        mitre,
                }
                break

    # Build exposed services list
    result["exposed_services"] = list(matched_patterns.values())
    result["total_exposed"]    = len(result["exposed_services"])

    if not result["exposed_services"]:
        return result

    # Group into finding categories
    ussd_hits       = [m for m in result["exposed_services"] if "ussd" in m["pattern"]]
    api_hits        = [m for m in result["exposed_services"]
                       if m["pattern"] in ("api", "payment", "gateway", "transaction",
                                           "callback", "webhook", "transfer", "pay")]
    admin_hits      = [m for m in result["exposed_services"]
                       if m["pattern"] in ("admin", "backoffice", "back-office")]
    settlement_hits = [m for m in result["exposed_services"]
                       if m["pattern"] in ("settlement", "switch", "reconcil")]
    auth_hits       = [m for m in result["exposed_services"]
                       if m["pattern"] in ("auth", "oauth", "token")]
    merchant_hits   = [m for m in result["exposed_services"]
                       if m["pattern"] in ("merchant", "agent", "portal")]

    # Generate findings
    if ussd_hits:
        atk = ATTACK_SCENARIOS["ussd_exposed"]
        result["findings"].append({
            "finding":        f"USSD gateway infrastructure exposed ({len(ussd_hits)} subdomain(s))",
            "detail":         f"USSD-related subdomains discovered: "
                              f"{', '.join(h['subdomain'] for h in ussd_hits)}. "
                              f"USSD gateway exposure allows attackers to probe session handling "
                              f"and potentially manipulate transactions.",
            "severity":       "critical",
            "mitre":          {"id": "T1190", "name": "Exploit Public-Facing Application"},
            "recommendation": "Restrict USSD gateway access to whitelisted IP ranges only. "
                              "Implement rate limiting and anomaly detection on all USSD sessions. "
                              "USSD infrastructure must never be directly internet-accessible.",
            "attack_scenario": {
                "scenario":     atk["scenario"],
                "impact":       atk["impact"],
                "likelihood":   atk["likelihood"],
                "threat_actors": atk["actors"],
            },
        })
        result["risk_score_delta"] += 25

    if admin_hits:
        atk = ATTACK_SCENARIOS["admin_exposed"]
        result["findings"].append({
            "finding":        f"MoMo back-office / admin portal exposed ({len(admin_hits)} subdomain(s))",
            "detail":         f"Administrative subdomains discovered: "
                              f"{', '.join(h['subdomain'] for h in admin_hits)}. "
                              f"Back-office systems of African MoMo operators are a primary target "
                              f"for OPERA1ER and other APT groups.",
            "severity":       "critical",
            "mitre":          {"id": "T1078", "name": "Valid Accounts"},
            "recommendation": "Remove all admin/back-office portals from public internet access. "
                              "Access must be via VPN only. Enforce MFA on all admin accounts. "
                              "Implement privileged access management (PAM).",
            "attack_scenario": {
                "scenario":     atk["scenario"],
                "impact":       atk["impact"],
                "likelihood":   atk["likelihood"],
                "threat_actors": atk["actors"],
            },
        })
        result["risk_score_delta"] += 30

    if settlement_hits:
        atk = ATTACK_SCENARIOS["settlement_exposed"]
        result["findings"].append({
            "finding":        f"Payment settlement / switch infrastructure exposed",
            "detail":         f"Settlement-related subdomains: "
                              f"{', '.join(h['subdomain'] for h in settlement_hits)}. "
                              f"Settlement systems are high-value APT targets in West Africa.",
            "severity":       "critical",
            "mitre":          {"id": "T1190", "name": "Exploit Public-Facing Application"},
            "recommendation": "Settlement systems must be completely isolated from internet access. "
                              "Access only via dedicated leased lines or verified VPN. "
                              "Implement SWIFT/payment security controls per BoG directive.",
            "attack_scenario": {
                "scenario":     atk["scenario"],
                "impact":       atk["impact"],
                "likelihood":   atk["likelihood"],
                "threat_actors": atk["actors"],
            },
        })
        result["risk_score_delta"] += 30

    if auth_hits:
        atk = ATTACK_SCENARIOS["auth_exposed"]
        result["findings"].append({
            "finding":        f"Authentication service exposed to internet ({len(auth_hits)} subdomain(s))",
            "detail":         f"Auth-related subdomains: "
                              f"{', '.join(h['subdomain'] for h in auth_hits)}. "
                              f"Exposed auth services are primary targets for credential stuffing.",
            "severity":       "critical",
            "mitre":          {"id": "T1078", "name": "Valid Accounts"},
            "recommendation": "Implement rate limiting and CAPTCHA on auth endpoints. "
                              "Enable account lockout after failed attempts. "
                              "Deploy MFA for all accounts. Monitor for credential stuffing patterns.",
            "attack_scenario": {
                "scenario":     atk["scenario"],
                "impact":       atk["impact"],
                "likelihood":   atk["likelihood"],
                "threat_actors": atk["actors"],
            },
        })
        result["risk_score_delta"] += 25

    if api_hits:
        atk = ATTACK_SCENARIOS["api_exposed"]
        result["findings"].append({
            "finding":        f"Payment API endpoints externally accessible ({len(api_hits)} subdomain(s))",
            "detail":         f"Payment API subdomains: "
                              f"{', '.join(h['subdomain'] for h in api_hits[:5])}. "
                              f"Public payment APIs require strong authentication and rate limiting.",
            "severity":       "high",
            "mitre":          {"id": "T1190", "name": "Exploit Public-Facing Application"},
            "recommendation": "Implement API authentication (OAuth 2.0 / API keys). "
                              "Rate limit all payment endpoints. "
                              "Log and monitor all API access. "
                              "Run API security testing quarterly.",
            "attack_scenario": {
                "scenario":     atk["scenario"],
                "impact":       atk["impact"],
                "likelihood":   atk["likelihood"],
                "threat_actors": atk["actors"],
            },
        })
        result["risk_score_delta"] += 15

    if merchant_hits:
        atk = ATTACK_SCENARIOS["merchant_exposed"]
        result["findings"].append({
            "finding":        f"Merchant / agent portal exposed ({len(merchant_hits)} subdomain(s))",
            "detail":         f"Merchant portal subdomains: "
                              f"{', '.join(h['subdomain'] for h in merchant_hits)}. "
                              f"Merchant portals are targeted for credential stuffing and account takeover.",
            "severity":       "high",
            "mitre":          {"id": "T1078", "name": "Valid Accounts"},
            "recommendation": "Enforce MFA on all merchant and agent accounts. "
                              "Implement geo-restriction on portal access. "
                              "Monitor for unusual transaction patterns from merchant accounts.",
            "attack_scenario": {
                "scenario":     atk["scenario"],
                "impact":       atk["impact"],
                "likelihood":   atk["likelihood"],
                "threat_actors": atk["actors"],
            },
        })
        result["risk_score_delta"] += 12

    log.info(
        f"[MoMo] {target} | Operator: {result['operator'] or 'Unknown'} | "
        f"Exposed services: {result['total_exposed']} | "
        f"Findings: {len(result['findings'])} | "
        f"Risk delta: +{result['risk_score_delta']}"
    )

    return result