"""
SankofahEye — Technology Fingerprinting
AfriWealth Cyber Intelligence

Parses URLScan.io scan data to detect:
  - Web server software (Apache, Nginx, IIS, Caddy…)
  - CMS / frameworks (WordPress, Joomla, Drupal, Django…)
  - CDN / WAF providers (Cloudflare, Akamai, Incapsula…)
  - Analytics / tracking (Google Analytics, Hotjar…)
  - JavaScript libraries (jQuery, React, Angular…)
  - E-commerce platforms (WooCommerce, Magento, Shopify…)

Then passively maps detected technologies to known CVE classes
using a curated local lookup — no external API calls needed.

Output is merged into the aggregated findings dict and rendered
as a new "Technology Fingerprint" section in both PDFs.
"""

import re
from utils.logger import SankofahLogger

log = SankofahLogger("tech_fingerprint")


# ─── Technology detection rules ───────────────────────────────────────────────
# Each rule: (canonical_name, category, [regex patterns to match against raw text])

TECH_RULES = [
    # ── Web servers
    ("Apache",          "Web Server",   [r"apache[\s/]?([\d.]+)?", r'"server":\s*"apache']),
    ("Nginx",           "Web Server",   [r"nginx[\s/]?([\d.]+)?",  r'"server":\s*"nginx']),
    ("Microsoft IIS",   "Web Server",   [r"iis[\s/]?([\d.]+)?",    r'"server":\s*"microsoft-iis']),
    ("LiteSpeed",       "Web Server",   [r"litespeed",             r'"server":\s*"litespeed']),
    ("Caddy",           "Web Server",   [r'"server":\s*"caddy']),
    ("OpenResty",       "Web Server",   [r"openresty"]),

    # ── CMS / Frameworks
    ("WordPress",       "CMS",          [r"wp-content", r"wp-includes", r"wordpress"]),
    ("Joomla",          "CMS",          [r"/components/com_", r"joomla"]),
    ("Drupal",          "CMS",          [r"drupal", r"sites/default/files"]),
    ("Django",          "Framework",    [r"csrftoken", r"django"]),
    ("Laravel",         "Framework",    [r"laravel_session", r"laravel"]),
    ("Ruby on Rails",   "Framework",    [r"_rails_",  r"x-powered-by.*rails"]),
    ("ASP.NET",         "Framework",    [r"asp\.net", r"__viewstate", r"aspnet"]),
    ("PHP",             "Language",     [r"x-powered-by.*php[\s/]?([\d.]+)?", r"\.php"]),

    # ── CDN / WAF
    ("Cloudflare",      "CDN/WAF",      [r"cloudflare", r"cf-ray", r"__cfduid"]),
    ("Akamai",          "CDN/WAF",      [r"akamai", r"akamaiedge", r"x-check-cacheable"]),
    ("Fastly",          "CDN/WAF",      [r"fastly", r"x-fastly"]),
    ("Incapsula",       "CDN/WAF",      [r"incap_ses", r"visid_incap", r"incapsula"]),
    ("AWS CloudFront",  "CDN/WAF",      [r"cloudfront\.net", r"x-amz-cf-id"]),
    ("Sucuri",          "CDN/WAF",      [r"sucuri", r"x-sucuri"]),

    # ── Analytics / Tracking
    ("Google Analytics","Analytics",    [r"google-analytics\.com", r"gtag\(", r"ga\.js", r"analytics\.js"]),
    ("Google Tag Mgr",  "Analytics",    [r"googletagmanager\.com", r"gtm\.js"]),
    ("Hotjar",          "Analytics",    [r"hotjar\.com", r"hj\("]),
    ("Matomo",          "Analytics",    [r"matomo\.js", r"piwik\.js"]),
    ("Facebook Pixel",  "Analytics",    [r"connect\.facebook\.net", r"fbevents\.js"]),

    # ── JavaScript libraries
    ("jQuery",          "JavaScript",   [r"jquery[\.-]([\d.]+)?\.min\.js", r"jquery\.js"]),
    ("React",           "JavaScript",   [r"react[\.-]([\d.]+)?\.js", r"__react"]),
    ("Angular",         "JavaScript",   [r"angular[\.-]([\d.]+)?\.js", r"ng-version"]),
    ("Vue.js",          "JavaScript",   [r"vue[\.-]([\d.]+)?\.js", r"__vue"]),
    ("Bootstrap",       "CSS Framework",[r"bootstrap[\.-]([\d.]+)?\.min\.css",
                                         r"bootstrap[\.-]([\d.]+)?\.js"]),

    # ── E-commerce
    ("WooCommerce",     "E-Commerce",   [r"woocommerce", r"wc-ajax"]),
    ("Magento",         "E-Commerce",   [r"magento", r"mage/"]),
    ("Shopify",         "E-Commerce",   [r"shopify\.com", r"cdn\.shopify"]),
    ("OpenCart",        "E-Commerce",   [r"opencart", r"route=common"]),

    # ── Mail / Hosting services (common in Ghana)
    ("cPanel",          "Hosting Panel",[r"cpanel", r"whm\."]),
    ("Plesk",           "Hosting Panel",[r"plesk", r"parallels"]),
    ("Zimbra",          "Mail Server",  [r"zimbra"]),
    ("Roundcube",       "Mail Server",  [r"roundcube", r"rcmloginuser"]),
    ("Microsoft 365",   "Mail Service", [r"mail\.protection\.outlook\.com",
                                         r"outlook\.com.*mx"]),
]


# ─── CVE risk mapping ──────────────────────────────────────────────────────────
# Maps technology name → known vulnerability classes with MITRE technique.
# Passive only — we flag the risk class, not specific CVE numbers
# (those require version-specific scanning beyond OSINT scope).

TECH_CVE_MAP = {
    "WordPress": {
        "risk":        "HIGH",
        "cve_class":   "Plugin/theme RCE, SQL injection, XSS, admin takeover",
        "note":        "WordPress is the most exploited CMS globally. Outdated plugins "
                       "and themes are the primary initial access vector.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Keep WordPress core, plugins, and themes updated. "
                       "Use a WAF. Disable XML-RPC if unused. Change default admin URL.",
    },
    "Joomla": {
        "risk":        "HIGH",
        "cve_class":   "Authentication bypass, SQL injection, RCE via extensions",
        "note":        "Joomla has a history of critical authentication bypass CVEs.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Update Joomla core and all extensions. Audit installed extensions.",
    },
    "Drupal": {
        "risk":        "HIGH",
        "cve_class":   "Drupalgeddon RCE (CVE-2018-7600 / CVE-2018-7602 class)",
        "note":        "Drupal RCE vulnerabilities (Drupalgeddon) are actively exploited.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Keep Drupal core updated. Apply security advisories immediately.",
    },
    "Apache": {
        "risk":        "MEDIUM",
        "cve_class":   "Path traversal (CVE-2021-41773 class), mod_* misconfigurations",
        "note":        "Apache path traversal CVEs have been exploited in the wild.",
        "mitre":       "T1083 — File and Directory Discovery",
        "remediation": "Update Apache to latest stable. Audit mod_* modules. "
                       "Disable directory listing.",
    },
    "Nginx": {
        "risk":        "LOW",
        "cve_class":   "Off-by-one vulnerabilities, misconfiguration-based path traversal",
        "note":        "Nginx CVEs are less frequent but misconfigurations are common.",
        "mitre":       "T1083 — File and Directory Discovery",
        "remediation": "Keep Nginx updated. Review location blocks for path traversal.",
    },
    "Microsoft IIS": {
        "risk":        "MEDIUM",
        "cve_class":   "HTTP.sys vulnerabilities, WebDAV exploitation, buffer overflow",
        "note":        "IIS vulnerabilities are regularly targeted in enterprise environments.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Apply Windows/IIS patches promptly. Disable WebDAV if unused.",
    },
    "ASP.NET": {
        "risk":        "MEDIUM",
        "cve_class":   "ViewState deserialization RCE, padding oracle attacks",
        "note":        "ASP.NET ViewState without MachineKey encryption enables RCE.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Encrypt ViewState with MachineKey. Apply .NET security patches.",
    },
    "PHP": {
        "risk":        "MEDIUM",
        "cve_class":   "RCE via unsafe functions, file inclusion, type juggling",
        "note":        "PHP version exposure aids targeted exploitation.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Update PHP to a supported version. Disable dangerous functions "
                       "(eval, exec, system). Hide PHP version in headers.",
    },
    "cPanel": {
        "risk":        "HIGH",
        "cve_class":   "Privilege escalation, credential exposure via shared hosting",
        "note":        "Exposed cPanel is a high-value target for account takeover.",
        "mitre":       "T1078 — Valid Accounts",
        "remediation": "Restrict cPanel access by IP. Enforce MFA. "
                       "Keep cPanel updated.",
    },
    "Zimbra": {
        "risk":        "CRITICAL",
        "cve_class":   "Zero-day RCE (CVE-2022-27925, CVE-2023-37580 class), "
                       "pre-auth SSRF, webmail credential harvesting",
        "note":        "Zimbra is actively targeted by nation-state actors and "
                       "ransomware groups. Multiple critical CVEs in 2022-2024.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Update Zimbra immediately. Apply all security patches. "
                       "Consider migration to a managed cloud mail provider.",
    },
    "Roundcube": {
        "risk":        "HIGH",
        "cve_class":   "XSS to RCE (CVE-2023-43770 class), stored XSS via email",
        "note":        "Roundcube RCE via stored XSS was exploited by APT28 in 2023.",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "remediation": "Update Roundcube immediately. Enforce MFA on webmail access.",
    },
    "WooCommerce": {
        "risk":        "HIGH",
        "cve_class":   "Payment skimming, order injection, privilege escalation",
        "note":        "WooCommerce sites are targeted for payment card skimming.",
        "mitre":       "T1056.003 — Input Capture: Web Portal Capture",
        "remediation": "Keep WooCommerce and plugins updated. Use a payment security "
                       "scanner. Implement CSP headers.",
    },
}


# ─── Version extraction ────────────────────────────────────────────────────────

def _extract_version(text: str, pattern: str) -> str:
    """Attempt to extract a version number from matched text."""
    m = re.search(pattern, text, re.IGNORECASE)
    if m and m.lastindex and m.group(1):
        v = m.group(1).strip("./- ")
        if re.match(r"^\d[\d.]+$", v):
            return v
    return ""


# ─── Core fingerprinting function ─────────────────────────────────────────────

def fingerprint(urlscan_data: dict, vt_data: dict) -> dict:
    """
    Detect technologies from URLScan and VirusTotal data.

    Args:
        urlscan_data: The urlscan dict from vt_urlscan_module results
        vt_data:      The virustotal dict from vt_urlscan_module results

    Returns:
        dict with keys:
            technologies: list of detected tech dicts
            cve_risks:    list of tech with known vulnerability classes
            risk_count:   int
            high_risk_tech: list of tech names with HIGH/CRITICAL CVE class
    """
    result = {
        "technologies":     [],
        "cve_risks":        [],
        "risk_count":       0,
        "high_risk_tech":   [],
        "status":           "ok",
    }

    # Build a blob of all text to match against
    raw_parts = []

    # URLScan: server headers, URLs, technologies list
    for scan in urlscan_data.get("scans", []):
        if scan.get("server"):
            raw_parts.append(scan["server"].lower())
        if scan.get("url"):
            raw_parts.append(scan["url"].lower())

    for tech in urlscan_data.get("technologies", []):
        raw_parts.append(str(tech).lower())

    # VT: categories
    for cat in vt_data.get("categories", []):
        raw_parts.append(str(cat).lower())

    raw_blob = " ".join(raw_parts)

    if not raw_blob.strip():
        result["status"] = "no_data"
        return result

    detected = {}

    for tech_name, category, patterns in TECH_RULES:
        for pattern in patterns:
            if re.search(pattern, raw_blob, re.IGNORECASE):
                if tech_name not in detected:
                    version = _extract_version(raw_blob, pattern)
                    detected[tech_name] = {
                        "name":     tech_name,
                        "category": category,
                        "version":  version,
                    }
                break

    result["technologies"] = sorted(detected.values(), key=lambda x: x["category"])

    # Map to CVE risks
    for tech in result["technologies"]:
        name = tech["name"]
        if name in TECH_CVE_MAP:
            cve_entry = TECH_CVE_MAP[name].copy()
            cve_entry["tech"]    = name
            cve_entry["version"] = tech.get("version", "")
            result["cve_risks"].append(cve_entry)

            if cve_entry["risk"] in ("HIGH", "CRITICAL"):
                result["high_risk_tech"].append(name)

    result["risk_count"] = len(result["cve_risks"])

    if result["technologies"]:
        log.info(
            f"[TechFingerprint] Detected {len(result['technologies'])} technologies | "
            f"CVE risks: {result['risk_count']} | "
            f"High/Critical: {len(result['high_risk_tech'])}"
        )

    return result