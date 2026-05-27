"""
SankofahEye — Risk Scoring Engine
AfriWealth Cyber Intelligence

Calculates an overall risk score (0–100), per-finding severity ratings,
MITRE ATT&CK mappings, and attack scenario narratives per finding.
"""

from utils.logger import SankofahLogger

log = SankofahLogger("risk_scorer")
EXPIRY_CRITICAL_DAYS = 14
EXPIRY_WARNING_DAYS  = 30

# ── MITRE ATT&CK Mappings ────────────────────────────────────
MITRE_MAPPINGS = {
    "subdomain_exposure":    {"id": "T1596.001", "name": "Search Open Technical Databases: DNS/Passive DNS"},
    "email_harvesting":      {"id": "T1589.002", "name": "Gather Victim Identity Info: Email Addresses"},
    "exposed_rdp":           {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
    "exposed_ssh":           {"id": "T1021.004", "name": "Remote Services: SSH"},
    "exposed_database":      {"id": "T1190",     "name": "Exploit Public-Facing Application"},
    "credential_leak":       {"id": "T1589.001", "name": "Gather Victim Identity Info: Credentials"},
    "dark_web_mention":      {"id": "T1597",     "name": "Search Closed Sources"},
    "malware_flag":          {"id": "T1584",     "name": "Compromise Infrastructure"},
    "open_smb":              {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"},
    "open_ftp":              {"id": "T1071.002", "name": "Application Layer Protocol: File Transfer"},
    "mail_infrastructure":   {"id": "T1566",     "name": "Phishing"},
    "webmail_exposure":      {"id": "T1078",     "name": "Valid Accounts"},
    "email_spoofing": {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
    "dns_spoofing":   {"id": "T1584.002", "name": "Compromise Infrastructure: DNS Server"}, 
    "ssl_expired":     {"id": "T1600",     "name": "Weaken Encryption"},
    "ssl_self_signed": {"id": "T1553.004", "name": "Subvert Trust Controls: Install Root Certificate"},
}

# ── Attack Scenario Templates ─────────────────────────────────
ATTACK_SCENARIOS = {
    "subdomain_exposure": {
        "scenario": (
            "A threat actor conducting passive reconnaissance against {target} would enumerate "
            "these subdomains within minutes using free tools. Each subdomain represents a potential "
            "entry point — development environments often run outdated software, mail servers may "
            "accept unauthenticated relaying, and forgotten subdomains may host unpatched legacy applications."
        ),
        "impact": (
            "Initial access to any subdomain can be leveraged for lateral movement into the core "
            "infrastructure. In the Ghanaian public sector context, compromised government subdomains "
            "have been used to host phishing pages targeting citizens applying for services."
        ),
        "likelihood": "HIGH — subdomain enumeration is the first step in virtually every targeted attack.",
        "threat_actors": "Opportunistic cybercriminals, BEC groups targeting .gov.gh domains, hacktivists.",
    },
    "mail_infrastructure": {
        "scenario": (
            "The presence of mail, webmail, and IMAP subdomains indicates a self-hosted email "
            "infrastructure. Threat actors would target {target}'s webmail portal with credential "
            "stuffing attacks using breach databases, then use compromised mailboxes to launch "
            "Business Email Compromise (BEC) attacks impersonating officials."
        ),
        "impact": (
            "A compromised government email account enables fraudulent communications to citizens, "
            "partner agencies, and financial institutions. In Ghana's public sector, BEC attacks "
            "have been used to redirect procurement payments and distribute malware to contractors."
        ),
        "likelihood": "HIGH — webmail portals are among the most targeted assets in public sector attacks.",
        "threat_actors": "BEC groups (particularly West Africa-based), nation-state actors, opportunistic phishers.",
    },
    "exposed_rdp": {
        "scenario": (
            "An internet-exposed RDP port on {target} would be discovered by automated scanners "
            "within hours. Threat actors would launch credential stuffing using leaked government "
            "email/password combinations from prior breaches, followed by brute-force attempts "
            "using common patterns (Welcome1, Password123, organisation name + year)."
        ),
        "impact": (
            "Successful RDP compromise gives an adversary direct interactive access to the target "
            "system. Standard post-exploitation path: privilege escalation, lateral movement across "
            "internal network, data exfiltration, and ransomware deployment. Average ransom demand "
            "for African government institutions has ranged from $50,000 to $500,000."
        ),
        "likelihood": "CRITICAL — exposed RDP is the single most common ransomware initial access vector globally.",
        "threat_actors": "Ransomware affiliates (LockBit, BlackCat), initial access brokers selling .gov.gh access.",
    },
    "exposed_ssh": {
        "scenario": (
            "An exposed SSH service on {target} would be targeted by automated brute-force tools "
            "running 24/7 from botnet infrastructure. Threat actors would also test for default "
            "credentials and attempt to exploit known SSH vulnerabilities if the service version "
            "is outdated."
        ),
        "impact": (
            "Compromised SSH access provides persistent shell access to the server. Attackers "
            "would install backdoors, cryptocurrency miners, or use the server as a pivot point "
            "for attacks against other government infrastructure on the same network segment."
        ),
        "likelihood": "HIGH — SSH brute-force is fully automated and runs continuously against all exposed IPs.",
        "threat_actors": "Cryptomining groups, botnet operators, APT groups using SSH for persistent access.",
    },
    "exposed_database": {
        "scenario": (
            "An internet-accessible database on {target} would be discovered by Shodan within "
            "24 hours of exposure. If authentication is absent or uses default credentials, "
            "automated scanners will dump the entire database. Tools like sqlmap and NoSQLMap "
            "automate this attack completely — no human involvement needed."
        ),
        "impact": (
            "Database exposure would compromise all stored citizen data — scholarship applications, "
            "personal identification numbers, financial records, and contact details. This data "
            "would be sold on dark web markets or used for targeted fraud against Ghanaian citizens. "
            "Under Ghana's Data Protection Act 2012 (Act 843), this constitutes a reportable breach "
            "with significant regulatory consequences."
        ),
        "likelihood": "CRITICAL — exposed databases are exploited within hours of discovery by automated tools.",
        "threat_actors": "Data brokers, identity theft rings, opportunistic cybercriminals scanning Shodan.",
    },
    "open_smb": {
        "scenario": (
            "An exposed SMB port on {target} would be immediately tested for the EternalBlue "
            "vulnerability (MS17-010) which enabled the 2017 WannaCry ransomware outbreak. "
            "Even patched systems remain targets for credential relay attacks (NTLM relay) "
            "which can be executed without any valid credentials."
        ),
        "impact": (
            "SMB exploitation typically results in full domain compromise. WannaCry and NotPetya "
            "variants still circulate and specifically target unpatched SMB services. A successful "
            "attack would encrypt all accessible file shares and demand ransom, potentially "
            "destroying years of government records."
        ),
        "likelihood": "CRITICAL — automated EternalBlue scanning is continuous across all internet-facing IPs.",
        "threat_actors": "Ransomware groups, worm propagation (WannaCry variants), nation-state actors.",
    },
    "open_ftp": {
        "scenario": (
            "An exposed FTP service on {target} would be tested for anonymous authentication "
            "and default credentials. FTP transmits credentials in plaintext, meaning any "
            "network interception between the client and server exposes login details. "
            "Threat actors would also test for FTP bounce attacks to use the server as a proxy."
        ),
        "impact": (
            "Anonymous FTP access exposes all readable files on the server. Writable FTP directories "
            "allow attackers to upload malware, defacement content, or use the server as a malware "
            "distribution point — leading to the organisation's domain being blacklisted by "
            "security vendors."
        ),
        "likelihood": "HIGH — automated FTP scanning and anonymous login testing is standard recon procedure.",
        "threat_actors": "Web defacement groups, malware distributors, opportunistic data thieves.",
    },
    "credential_leak": {
        "scenario": (
            "Leaked credentials for {target} staff are actively traded on dark web markets and "
            "Telegram channels. Threat actors purchase breach databases and run automated "
            "credential stuffing attacks against the organisation's webmail, VPN, and admin "
            "portals. A single valid credential set can bypass all perimeter defences entirely."
        ),
        "impact": (
            "Credential-based attacks leave minimal forensic traces compared to exploits — "
            "the attacker looks like a legitimate user. In the Ghanaian context, compromised "
            "government credentials have been used for procurement fraud, unauthorised data "
            "access, and impersonation of officials in BEC schemes targeting international partners."
        ),
        "likelihood": "CRITICAL — credential stuffing attacks are fully automated and run continuously.",
        "threat_actors": "BEC groups, initial access brokers, insider threat actors, nation-state intelligence.",
    },
    "dark_web_mention": {
        "scenario": (
            "Dark web mentions of {target} indicate the organisation is already on threat actors' "
            "radar. Mentions may include leaked internal documents, access listings (threat actors "
            "selling established access), or discussions about vulnerabilities in the organisation's "
            "infrastructure in closed forums."
        ),
        "impact": (
            "Active dark web presence dramatically increases attack probability. If access is being "
            "sold, the organisation may already be compromised without knowing it. Data listed for "
            "sale erodes citizen trust and may violate Ghana's Data Protection Act obligations "
            "around breach notification."
        ),
        "likelihood": "CRITICAL — active listings indicate imminent or ongoing threat.",
        "threat_actors": "Initial access brokers, ransomware affiliates, data extortion groups.",
    },
    "malware_flag": {
        "scenario": (
            "VirusTotal flags on {target}'s domain indicate the organisation's infrastructure "
            "has been associated with malware distribution, phishing, or command-and-control "
            "activity. This may indicate a prior compromise where the server was weaponised, "
            "or a subdomain hijack where attackers took control of an abandoned subdomain."
        ),
        "impact": (
            "A malware-flagged domain is blacklisted by security vendors, email providers, and "
            "browsers. Citizens visiting the site receive security warnings. Emails sent from "
            "the domain land in spam or are blocked entirely, disrupting government communications. "
            "Removing blacklist status can take weeks even after the malware is removed."
        ),
        "likelihood": "HIGH — flags indicate active or recent compromise requiring immediate investigation.",
        "threat_actors": "Phishing kit operators, botnet C2 infrastructure abusers, web shell deployers.",
    },
    "email_harvesting": {
        "scenario": (
            "Harvested email addresses from {target} provide threat actors with verified targets "
            "for spear-phishing campaigns. With staff email patterns identified (e.g. "
            "firstname.lastname@domain), attackers can construct additional valid addresses "
            "for the entire organisation and launch highly targeted social engineering attacks."
        ),
        "impact": (
            "Spear-phishing using real staff email addresses has a significantly higher success "
            "rate than generic phishing. A single successful phish against a finance or IT staff "
            "member can lead to full network compromise. In Ghana's public sector, phishing "
            "remains the primary initial access vector for both criminal and nation-state actors."
        ),
        "likelihood": "HIGH — email harvesting is passive, free, and the foundation of most targeted attacks.",
        "threat_actors": "BEC groups, ransomware initial access brokers, nation-state APT groups.",
    },
    "missing_dmarc": {
    "scenario": (
        "Without DMARC enforcement, any threat actor can send emails that appear to come "
        "from {target}'s domain — with zero technical barrier. Tools like Gophish or "
        "SET (Social Engineering Toolkit) make this a five-minute attack. The spoofed "
        "email passes basic checks and lands directly in the victim's inbox."
    ),
    "impact": (
        "Email spoofing of a government or financial domain in Ghana enables highly "
        "convincing BEC attacks, fraudulent citizen communications, and phishing campaigns "
        "that leverage the authority and trust of the impersonated institution. Victims "
        "have no technical way to distinguish the fake email from a real one."
    ),
    "likelihood": "CRITICAL — no technical skill required, tools are free and widely available.",
    "threat_actors": "BEC groups, phishing-as-a-service operators, opportunistic fraudsters.",
},
"weak_spf": {
    "scenario": (
        "A weak or missing SPF record on {target} means mail servers have no authoritative "
        "list of which IPs are allowed to send email for this domain. Attackers configure "
        "any VPS to send as @{target} and bypass basic spam filters."
    ),
    "impact": (
        "Spoofed emails from trusted domains bypass many corporate email filters. "
        "In Ghana's banking and government context, an email appearing to come from "
        "an official domain is inherently trusted by recipients — staff, citizens, and partners."
    ),
    "likelihood": "HIGH — SPF bypass is standard practice in phishing kit deployment.",
    "threat_actors": "Mass phishing operators, BEC groups, ransomware initial access brokers.",
},
"ssl_expired": {
    "scenario": (
        "An expired certificate on {target} creates multiple attack opportunities. "
        "Users who click through the browser warning expose themselves to man-in-the-middle "
        "attacks. Threat actors can serve a cloned site using a valid certificate while "
        "the legitimate site shows warnings — training users to ignore security errors."
    ),
    "impact": (
        "Expired certificates erode user trust and expose traffic to interception. "
        "In Ghana's banking context, users accustomed to ignoring certificate warnings "
        "on legitimate sites become easy targets for credential-harvesting phishing pages. "
        "Regulatory bodies may also flag expired certificates as a compliance failure."
    ),
    "likelihood": "HIGH — certificate expiry is exploited opportunistically and continuously.",
    "threat_actors": "Phishing operators, man-in-the-middle attackers, credential harvesters.",
},
"ssl_self_signed": {
    "scenario": (
        "Self-signed certificates on {target} subdomains indicate either test environments "
        "left exposed to the internet or misconfigured production services. Attackers use "
        "these as indicators of poorly maintained infrastructure likely to have other "
        "security gaps. The presence of self-signed certs also enables trivial MITM attacks "
        "since clients cannot validate the certificate chain."
    ),
    "impact": (
        "Self-signed certificates on internal-facing systems left internet-accessible "
        "expose sensitive administrative interfaces without proper identity verification. "
        "Test and staging environments often contain production data copies and have "
        "weaker security controls than production systems."
    ),
    "likelihood": "MEDIUM — frequently found alongside other misconfigurations.",
    "threat_actors": "Opportunistic attackers, internal threat actors, reconnaissance bots.",
},
}


DATABASE_PORTS = {1433, 1521, 3306, 5432, 27017, 6379}
RDP_PORTS      = {3389}
SSH_PORTS      = {22}
SMB_PORTS      = {445}
FTP_PORTS      = {21}

MAIL_SUBDOMAINS = {"mail", "webmail", "imap", "smtp", "mx", "email"}


def get_attack_scenario(key: str, target: str) -> dict:
    template = ATTACK_SCENARIOS.get(key, {})
    return {
        "scenario":      template.get("scenario", "").replace("{target}", target),
        "impact":        template.get("impact", "").replace("{target}", target),
        "likelihood":    template.get("likelihood", ""),
        "threat_actors": template.get("threat_actors", ""),
    }


def score(findings: dict, weights: dict) -> dict:
    log.info("[RiskScorer] Calculating risk score...")

    target         = findings.get("target", "target")
    raw_score      = 0.0
    finding_details = []
    mitre_techniques = set()

    # ── Subdomain count ───────────────────────────────────────
    sub_count = findings["subdomains"]["count"]
    subdomain_list = [s.split(".")[0] for s in findings["subdomains"]["list"]]

    if sub_count > 0:
        pts = weights.get("subdomain_count_high", 0.4) * min(sub_count * 2, 15)
        raw_score += pts
        finding_details.append({
            "finding": "External subdomain footprint identified",
            "detail": f"{sub_count} subdomains discovered and mapped",
            "severity": "medium" if sub_count > 10 else "low",
            "mitre": MITRE_MAPPINGS["subdomain_exposure"],
            "recommendation": "Audit all subdomains. Decommission unused ones. Implement DNS monitoring and certificate transparency alerting.",
            "attack_scenario": get_attack_scenario("subdomain_exposure", target),
        })
        mitre_techniques.add("T1596.001")

    # ── FTP subdomain / port exposure scoring ─────────────────
    # Detects ftp.* subdomains passively (T1071.002 already mapped)
    # Also catches port 21 from Censys if it slips through high_risk_ports
    ftp_subs = [
        s for s in findings["subdomains"]["list"]
        if s.lower().startswith("ftp.") or ".ftp." in s.lower()
    ]
    ftp_ports = FTP_PORTS & set(findings['exposed_services'].get('open_ports', []))

    if ftp_subs or ftp_ports:
        ftp_detail_parts = []
        if ftp_subs:
            ftp_detail_parts.append(
                f"FTP subdomain(s) discovered: {', '.join(ftp_subs[:5])}"
            )
        if ftp_ports:
            ftp_detail_parts.append("Port 21 (FTP) detected open on Censys")

        raw_score += 15
        finding_details.append({
            "finding": "FTP exposure detected — unencrypted file transfer",
            "detail": ". ".join(ftp_detail_parts) + ". FTP transmits credentials in cleartext.",
            "severity": "high",
            "mitre": MITRE_MAPPINGS["open_ftp"],
            "recommendation": (
                "Replace FTP with SFTP (port 22) or FTPS (port 990) for all file transfers. "
                "If FTP is not actively used, shut down the service and block port 21 at the "
                "perimeter firewall. FTP subdomains should be decommissioned or redirected. "
                "Audit FTP logs for unauthorised access attempts."
            ),
            "attack_scenario": get_attack_scenario("open_ftp", target),
        })
        mitre_techniques.add("T1071.002")

    # ── Mail infrastructure detection ─────────────────────────
    mail_subs = [s for s in subdomain_list if s in MAIL_SUBDOMAINS]
    if mail_subs:
        raw_score += 18
        finding_details.append({
            "finding": "Self-hosted mail infrastructure exposed",
            "detail": f"Mail-related subdomains detected: {', '.join(mail_subs)}. Webmail portal is internet-accessible.",
            "severity": "high",
            "mitre": MITRE_MAPPINGS["mail_infrastructure"],
            "recommendation": "Enforce MFA on webmail. Implement geo-blocking on login portals. Deploy anti-phishing controls (DMARC, DKIM, SPF). Consider migrating to a hardened cloud mail provider.",
            "attack_scenario": get_attack_scenario("mail_infrastructure", target),
        })
        mitre_techniques.add("T1566")
        mitre_techniques.add("T1078")

    # ── Email exposure ────────────────────────────────────────
    email_count = findings["emails"]["count"]
    if email_count > 0:
        pts = min(email_count * 1.5, 10)
        raw_score += pts
        finding_details.append({
            "finding": "Staff email addresses publicly harvestable",
            "detail": f"{email_count} email addresses harvested from public sources",
            "severity": "medium",
            "mitre": MITRE_MAPPINGS["email_harvesting"],
            "recommendation": "Train staff on phishing awareness. Implement email masking for public contacts. Deploy advanced anti-phishing at the mail gateway.",
            "attack_scenario": get_attack_scenario("email_harvesting", target),
        })
        mitre_techniques.add("T1589.002")

    # ── High-risk ports ───────────────────────────────────────
    open_ports = set(findings["exposed_services"]["open_ports"])

    if open_ports & RDP_PORTS:
        pts = weights.get("exposed_rdp", 1.0) * 25
        raw_score += pts
        finding_details.append({
            "finding": "RDP exposed to internet",
            "detail": "Port 3389 (RDP) is internet-accessible — primary ransomware entry vector",
            "severity": "critical",
            "mitre": MITRE_MAPPINGS["exposed_rdp"],
            "recommendation": "Immediately restrict RDP behind VPN or Zero Trust gateway. Enable NLA and MFA. Implement account lockout after 3 failed attempts.",
            "attack_scenario": get_attack_scenario("exposed_rdp", target),
        })
        mitre_techniques.add("T1021.001")

    if open_ports & SSH_PORTS:
        pts = weights.get("exposed_ssh_default", 0.9) * 15
        raw_score += pts
        finding_details.append({
            "finding": "SSH exposed to internet",
            "detail": "Port 22 (SSH) is publicly reachable",
            "severity": "high",
            "mitre": MITRE_MAPPINGS["exposed_ssh"],
            "recommendation": "Restrict SSH to known IPs via firewall. Enforce key-based auth. Disable password login. Change to non-standard port.",
            "attack_scenario": get_attack_scenario("exposed_ssh", target),
        })
        mitre_techniques.add("T1021.004")

    if open_ports & SMB_PORTS:
        pts = weights.get("open_database_port", 1.0) * 20
        raw_score += pts
        finding_details.append({
            "finding": "SMB port exposed — ransomware risk",
            "detail": "Port 445 (SMB) is internet-accessible — EternalBlue / ransomware propagation risk",
            "severity": "critical",
            "mitre": MITRE_MAPPINGS["open_smb"],
            "recommendation": "Block SMB at perimeter firewall immediately. Apply MS17-010 patch. Disable SMBv1 entirely.",
            "attack_scenario": get_attack_scenario("open_smb", target),
        })
        mitre_techniques.add("T1021.002")

    # FTP port 21 scoring is handled by the FTP exposure block above
    # (covers both ftp.* subdomains and open port 21 together)

    if open_ports & DATABASE_PORTS:
        pts = weights.get("open_database_port", 1.0) * 25
        raw_score += pts
        exposed_db_ports = open_ports & DATABASE_PORTS
        finding_details.append({
            "finding": "Database port(s) directly internet-accessible",
            "detail": f"Database ports exposed: {sorted(exposed_db_ports)}",
            "severity": "critical",
            "mitre": MITRE_MAPPINGS["exposed_database"],
            "recommendation": "Block all database ports at the perimeter firewall immediately. Databases must never be directly internet-facing. Place behind application layer with authentication.",
            "attack_scenario": get_attack_scenario("exposed_database", target),
        })
        mitre_techniques.add("T1190")

    # ── CVEs ──────────────────────────────────────────────────
    cves = findings["exposed_services"]["cves"]
    if cves:
        pts = min(len(cves) * 5, 20)
        raw_score += pts
        finding_details.append({
            "finding": f"{len(cves)} known CVE(s) detected on exposed services",
            "detail": f"Unpatched vulnerabilities: {', '.join(cves[:8])}{'...' if len(cves) > 8 else ''}",
            "severity": "critical" if len(cves) > 3 else "high",
            "mitre": MITRE_MAPPINGS["exposed_database"],
            "recommendation": "Apply all patches immediately. Prioritise internet-facing services. Run authenticated vulnerability scan. Implement a vulnerability management programme.",
            "attack_scenario": {
                "scenario": f"Threat actors scan for these specific CVEs using tools like Shodan and Nuclei. Exploit code for most CVEs is publicly available within days of disclosure. {target}'s unpatched services would be exploited automatically.",
                "impact": "CVE exploitation typically results in remote code execution, giving the attacker full control of the affected system without any credentials required.",
                "likelihood": "CRITICAL — automated CVE scanning is continuous and exploit code is freely available.",
                "threat_actors": "Ransomware affiliates, botnet operators, vulnerability scanners, nation-state actors.",
            },
        })

    # ── Credential leaks ──────────────────────────────────────
    breached = findings["credential_exposure"]["total_breached"]
    breach_names = findings["credential_exposure"]["breach_names"]
    if breached > 0:
        pts = weights.get("credential_leak", 0.9) * min(breached * 5, 25)
        raw_score += pts
        finding_details.append({
            "finding": "Staff credentials found in breach databases",
            "detail": f"{breached} account(s) compromised across breaches: {', '.join(breach_names[:5])}",
            "severity": "critical" if breached > 3 else "high",
            "mitre": MITRE_MAPPINGS["credential_leak"],
            "recommendation": "Force immediate password reset for all affected accounts. Enforce MFA across all systems. Audit login logs for credential stuffing attempts over the past 90 days.",
            "attack_scenario": get_attack_scenario("credential_leak", target),
        })
        mitre_techniques.add("T1589.001")

    # ── Dark web mentions ─────────────────────────────────────
    dw_high  = findings["dark_web"]["high_risk_mentions"]
    dw_total = findings["dark_web"]["total_mentions"]
    if dw_high > 0:
        pts = weights.get("darkweb_mention", 0.95) * min(dw_high * 8, 25)
        raw_score += pts
        finding_details.append({
            "finding": "High-risk dark web mentions detected",
            "detail": f"{dw_high} high-risk mention(s) of {target} on dark web indexes",
            "severity": "critical",
            "mitre": MITRE_MAPPINGS["dark_web_mention"],
            "recommendation": "Investigate all mentions immediately. Engage threat intelligence team. Monitor for access sale listings. Treat as potential active compromise until ruled out.",
            "attack_scenario": get_attack_scenario("dark_web_mention", target),
        })
        mitre_techniques.add("T1597")
    elif dw_total > 0:
        raw_score += 5
        finding_details.append({
            "finding": "Dark web presence detected",
            "detail": f"{dw_total} mention(s) — no high-risk keywords matched",
            "severity": "medium",
            "mitre": MITRE_MAPPINGS["dark_web_mention"],
            "recommendation": "Monitor regularly. Set up continuous dark web alerting for the domain.",
            "attack_scenario": get_attack_scenario("dark_web_mention", target),
        })

    # ── VirusTotal flags ──────────────────────────────────────
    malicious = findings["reputation"]["malicious_votes"]
    if malicious > 0:
        pts = weights.get("malware_flag", 0.85) * min(malicious * 3, 20)
        raw_score += pts
        finding_details.append({
            "finding": "Domain flagged malicious by security vendors",
            "detail": f"{malicious} vendor(s) flagged domain as malicious on VirusTotal",
            "severity": "critical" if malicious > 5 else "high",
            "mitre": MITRE_MAPPINGS["malware_flag"],
            "recommendation": "Investigate flagged URLs and IPs immediately. Check for subdomain hijacking. Submit false-positive disputes if clean. Audit web server for web shells.",
            "attack_scenario": get_attack_scenario("malware_flag", target),
        })
        mitre_techniques.add("T1584")


    # ── DNS security ──────────────────────────────────────────
    dns_sec    = findings.get("dns_security", {})
    spf        = dns_sec.get("spf", {})
    dmarc      = dns_sec.get("dmarc", {})
    dkim       = dns_sec.get("dkim", {})
    dns_issues = dns_sec.get("issue_count", 0)

    if dns_issues > 0 or dns_sec:

        # DMARC missing, none, or quarantine
        if not dmarc.get("present") or dmarc.get("policy") in ("none", "quarantine"):
            severity  = "high"   if not dmarc.get("present") or dmarc.get("policy") == "none" else "medium"
            pts       = 20       if severity == "high" else 10
            raw_score += pts
            finding_details.append({
                "finding": "DMARC not fully enforced — domain spoofing risk",
                "detail": (
                    "No DMARC record found — domain spoofing completely unrestricted"
                    if not dmarc.get("present")
                    else "DMARC policy is 'none' — monitoring only, no enforcement"
                    if dmarc.get("policy") == "none"
                    else (
                        "DMARC policy is 'quarantine' — spoofed emails go to spam but are NOT rejected. "
                        "A determined attacker's spoofed email can still reach the inbox if spam filters are bypassed."
                    )
                ),
                "severity": severity,
                "mitre": MITRE_MAPPINGS["email_spoofing"],
                "recommendation": (
                    "Upgrade DMARC policy to p=reject to fully block spoofed emails. "
                    "Sequence: p=none (monitor) → p=quarantine → p=reject. "
                    "Ensure rua= reporting address is set to monitor abuse attempts."
                ),
                "attack_scenario": get_attack_scenario("missing_dmarc", target),
            })
            mitre_techniques.add("T1566.001")

    # ── SSL/TLS certificates ──────────────────────────────────
    ssl_certs   = findings.get("ssl_certificates", {})
    ssl_expired = ssl_certs.get("expired", [])
    ssl_expiring = ssl_certs.get("expiring_soon", [])
    ssl_self_sig = ssl_certs.get("self_signed", [])
    ssl_weak     = ssl_certs.get("weak_protocol", [])

    if ssl_expired:
        pts = min(len(ssl_expired) * 15, 30)
        raw_score += pts
        finding_details.append({
            "finding": f"{len(ssl_expired)} expired SSL/TLS certificate(s) detected",
            "detail": (
                f"Expired certificates on: {', '.join(ssl_expired[:5])}"
                f"{'...' if len(ssl_expired) > 5 else ''}"
            ),
            "severity": "critical" if len(ssl_expired) > 2 else "high",
            "mitre": MITRE_MAPPINGS["ssl_expired"],
            "recommendation": (
                "Renew all expired certificates immediately. Implement automated certificate "
                "renewal (Let's Encrypt with certbot, or ACM if on AWS). Set calendar alerts "
                "30 and 7 days before expiry as a backup."
            ),
            "attack_scenario": get_attack_scenario("ssl_expired", target),
        })
        mitre_techniques.add("T1600")

    if ssl_expiring:
        pts = min(len(ssl_expiring) * 5, 15)
        raw_score += pts
        expiring_details = ", ".join(
            [f"{e['hostname']} ({e['days_remaining']}d)" for e in ssl_expiring[:3]]
        )
        finding_details.append({
            "finding": f"{len(ssl_expiring)} certificate(s) expiring within 30 days",
            "detail": f"Certificates expiring soon: {expiring_details}",
            "severity": "high" if any(
                e["days_remaining"] <= EXPIRY_CRITICAL_DAYS
                for e in ssl_expiring
            ) else "medium",
            "mitre": MITRE_MAPPINGS["ssl_expired"],
            "recommendation": (
                "Renew expiring certificates before they expire. Priority: any expiring "
                "within 14 days. Implement automated renewal to prevent future expiry."
            ),
            "attack_scenario": get_attack_scenario("ssl_expired", target),
        })
        mitre_techniques.add("T1600")

    if ssl_self_sig:
        pts = min(len(ssl_self_sig) * 8, 20)
        raw_score += pts
        finding_details.append({
            "finding": f"{len(ssl_self_sig)} self-signed certificate(s) detected",
            "detail": (
                f"Self-signed certificates on: {', '.join(ssl_self_sig[:5])}"
                f"{'...' if len(ssl_self_sig) > 5 else ''} — "
                f"indicates exposed test/dev environments or misconfigured services"
            ),
            "severity": "medium",
            "mitre": MITRE_MAPPINGS["ssl_self_signed"],
            "recommendation": (
                "Replace self-signed certificates with CA-signed certificates on all "
                "internet-facing services. Restrict access to test/dev environments "
                "via VPN or IP allowlisting — they should never be internet-accessible."
            ),
            "attack_scenario": get_attack_scenario("ssl_self_signed", target),
        })
        mitre_techniques.add("T1553.004")

    if ssl_weak:
        pts = min(len(ssl_weak) * 10, 20)
        raw_score += pts
        finding_details.append({
            "finding": f"Weak TLS protocol in use on {len(ssl_weak)} host(s)",
            "detail": (
                f"Hosts using deprecated TLS/SSL protocols: {', '.join(ssl_weak[:5])}"
            ),
            "severity": "high",
            "mitre": MITRE_MAPPINGS["ssl_expired"],
            "recommendation": (
                "Disable TLS 1.0 and TLS 1.1 on all servers. Enforce TLS 1.2 minimum, "
                "TLS 1.3 preferred. Update server configuration and test with SSL Labs."
            ),
            "attack_scenario": {
                "scenario": f"Weak TLS protocols on {target} are vulnerable to BEAST, POODLE, and CRIME attacks allowing traffic decryption.",
                "impact": "Encrypted traffic can be decrypted by network-positioned attackers, exposing credentials and session tokens.",
                "likelihood": "MEDIUM — requires network positioning but tools are freely available.",
                "threat_actors": "Nation-state actors, ISP-level interception, advanced persistent threats.",
            },
        })
        mitre_techniques.add("T1600")

        # SPF missing or weak
        spf_strength = spf.get("strength", "none")
        if spf_strength in ("none", "weak"):
            pts        = 15 if spf_strength == "none" else 8
            raw_score += pts
            finding_details.append({
                "finding": f"SPF record {'missing' if spf_strength == 'none' else 'weak (~all softfail)'}",
                "detail": (
                    "No SPF record found — any server can send email as this domain."
                    if spf_strength == "none"
                    else f"SPF uses ~all (softfail): {spf.get('record', '')} — spoofed emails may still be delivered."
                ),
                "severity": "high" if spf_strength == "none" else "medium",
                "mitre": MITRE_MAPPINGS["email_spoofing"],
                "recommendation": (
                    "Create an SPF record listing all authorised sending IPs ending with -all. "
                    "Example: v=spf1 include:_spf.google.com -all"
                ),
                "attack_scenario": get_attack_scenario("weak_spf", target),
            })
            mitre_techniques.add("T1566.001")

        # DKIM missing
        if not dkim.get("present"):
            raw_score += 8
            finding_details.append({
                "finding": "DKIM not configured — emails lack cryptographic signing",
                "detail": "No DKIM records found on common selectors. Emails cannot be cryptographically verified.",
                "severity": "medium",
                "mitre": MITRE_MAPPINGS["email_spoofing"],
                "recommendation": (
                    "Configure DKIM signing on your mail server. "
                    "Generate a key pair and publish the public key as a TXT record "
                    "at selector._domainkey.domain."
                ),
                "attack_scenario": {
                    "scenario": f"Without DKIM, emails from {target} cannot be verified as authentic. Attackers can intercept and modify emails in transit without detection.",
                    "impact": "Email tampering goes undetected. Combined with missing DMARC, domain impersonation is trivial.",
                    "likelihood": "HIGH — DKIM absence is a prerequisite for most email spoofing attacks.",
                    "threat_actors": "Man-in-the-middle operators, BEC groups, email tampering campaigns.",
                },
            })

    # ── Cap and normalise ─────────────────────────────────────
    final_score = min(round(raw_score), 100)

    if final_score >= 80:
        rating = "critical"; colour = "#D32F2F"
    elif final_score >= 60:
        rating = "high";     colour = "#F57C00"
    elif final_score >= 40:
        rating = "medium";   colour = "#FBC02D"
    else:
        rating = "low";      colour = "#388E3C"

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    finding_details.sort(key=lambda x: severity_order.get(x["severity"], 99))

    scoring = {
        "score":    final_score,
        "rating":   rating,
        "colour":   colour,
        "finding_count": len(finding_details),
        "findings": finding_details,
        "mitre_techniques": [
            {"id": tid, **MITRE_MAPPINGS.get(next(
                (k for k, v in MITRE_MAPPINGS.items() if v["id"] == tid), "subdomain_exposure"
            ), {"name": ""})}
            for tid in sorted(mitre_techniques)
        ],

    }

    log.info(
        f"[RiskScorer] Score: {final_score}/100 | "
        f"Rating: {rating.upper()} | "
        f"Findings: {len(finding_details)}"
    )
    return scoring