# AfriWealth Cyber Intelligence — Outreach Pack
**SankofahEye Launch Campaign | May 2026**
*DeCyberGuardian | afriwealthci.com | github.com/DeCyberGuardian/sankofaeye*

---

# PART 1 — EMAIL OUTREACH TEMPLATES

## Template A — CISO / IT Security Manager
**Tone:** Peer-to-peer. Technical credibility. You've already done the work.

---

**Subject:** SankofahEye found [X] exposure findings on [domain] — no charge, no obligation

Hi [First Name],

I'm a CTI practitioner based in Ghana and founder of AfriWealth Cyber Intelligence. Last week I ran a passive reconnaissance assessment of [domain] using SankofahEye — a tool I built specifically for Ghana's financial and public sector threat landscape.

The scan is passive only. No active exploitation, no systems touched. Pure OSINT — the same data any threat actor can access using free tools.

Here's what it found on [domain]:

- Overall risk score: [X]/100 — [LOW/MEDIUM/HIGH]
- [Finding 1 — e.g., DMARC not enforced — domain spoofing risk]
- [Finding 2 — e.g., Weak TLS on X hosts — T1600 Weaken Encryption]
- [Finding 3 — e.g., X subdomains mapped and externally visible]

I've attached the full SankofahEye report. It includes MITRE ATT&CK technique mapping, attack scenario narratives for each finding, and a 3-track remediation action plan (72-hour, 30-day, and 90-day).

No strings attached — the report is yours regardless of whether we ever speak again.

If any of these findings are news to you, or if you'd like to discuss what continuous passive monitoring would look like for [organisation], I'm happy to set up a 30-minute call.

AfriWealth CI provides ongoing passive exposure monitoring, threat-informed advisory, and reporting tailored to Ghana's regulatory context — BoG directives, NCA requirements, and the West African threat actor landscape.

Regards,
DeCyberGuardian
Founder, AfriWealth Cyber Intelligence
afriwealthci.com | github.com/DeCyberGuardian/sankofaeye

---

**PERSONALISATION GUIDE — CISO TEMPLATE:**
- bog.gov.gh → mention the 57 subdomains, weak TLS on 14 hosts, DMARC quarantine
- ghipss.com → lead with 67/100 HIGH, the 6 findings, ftp.ghipss.com exposed
- scholarships.gov.gh → lead with 77/100 HIGH, DMARC p=none on student application portal
- mtn.com.gh → lead with no SPF, no DMARC, no DKIM — full email spoofing exposure
- ecobank.com.gh → lead with completely missing email security records across the board

---

## Template B — CEO / Managing Director
**Tone:** Business risk, not technical. Financial exposure, regulatory framing, reputational stakes.

---

**Subject:** Your organisation's digital risk exposure — a briefing from AfriWealth Cyber Intelligence

Dear [Title] [Last Name],

I'm writing to bring a business risk matter to your attention.

AfriWealth Cyber Intelligence has conducted a passive digital exposure assessment of [organisation]. This is the same type of intelligence gathering that threat actors routinely perform before targeting financial institutions — and it requires no access to your systems whatsoever.

The assessment of [domain] returned a risk score of [X]/100 — [rating]. Among the findings:

**The most significant risk:** [Organisation]'s email domain currently has insufficient anti-spoofing controls. This means a criminal actor can send emails that appear to come from official [organisation] addresses — to staff, customers, partners, or regulators — with no technical barrier. This is the entry point for Business Email Compromise (BEC) fraud, which has cost West African financial institutions millions of cedis in misdirected payments and procurement fraud.

**Why this matters now:** Ghana's financial sector is under increasing attention from sophisticated threat actors who target weaknesses in payment infrastructure, mobile money ecosystems, and interbank communications. The Bank of Ghana's cybersecurity directives and the NCA's guidelines increasingly require institutions to demonstrate proactive digital risk management.

A full report of findings — including specific remediation actions for your IT team — is attached.

AfriWealth Cyber Intelligence provides Ghanaian financial institutions with ongoing passive exposure monitoring, executive-ready reporting, and intelligence-led security advisory services. Our work is grounded in Ghana's regulatory context and the real threat actor landscape operating in West Africa.

I would welcome the opportunity to brief you or your security leadership for 30 minutes at your convenience.

Respectfully,
DeCyberGuardian
Founder, AfriWealth Cyber Intelligence
afriwealthci.com

---

**PERSONALISATION GUIDE — CEO TEMPLATE:**
- For banks: reference BoG Cyber & Information Security Directive
- For telecoms: reference NCA cybersecurity obligations
- For government: reference Ghana's Data Protection Commission and public trust framing
- GHIPSS/settlement bodies: reference interbank trust and PAPSS implications
- Avoid deep technical language — focus on fraud, regulatory exposure, reputational risk

---

## Template C — Risk & Compliance Officer / Head of Internal Audit
**Tone:** Regulatory alignment. Gap between stated controls and actual exposure. Audit-friendly framing.

---

**Subject:** Passive exposure assessment of [domain] — compliance implications

Dear [First Name / Title],

I'm a CTI practitioner and founder of AfriWealth Cyber Intelligence, a Ghana-based threat intelligence firm focused on the financial sector and public institutions.

I recently completed a passive reconnaissance assessment of [domain] using SankofahEye, our open-source exposure intelligence platform. The assessment identified [X] findings with direct compliance implications.

Key findings relevant to your risk and compliance function:

**Email authentication gaps (SPF/DMARC/DKIM):** [Status from report]. Under the Bank of Ghana's Cyber and Information Security Directive and general IT risk management frameworks, inadequate email authentication controls represent a measurable gap in phishing and BEC risk management. These controls are also increasingly scrutinised in IT audit frameworks.

**Encryption protocol exposure:** [If applicable — TLS findings]. Deprecated TLS protocols represent a known vulnerability class (BEAST, POODLE, CRIME) with documented exploitation techniques. Their presence on production hosts is a finding that should appear in your next IT security audit.

**External attack surface visibility:** [X] subdomains are publicly enumerable. Without a subdomain inventory and monitoring programme, your organisation has incomplete visibility into its own attack surface — a gap in continuous control monitoring.

The full SankofahEye report is attached, including MITRE ATT&CK mappings and a 3-track remediation action plan structured around 72-hour, 30-day, and 90-day timelines — suitable for direct handoff to your IT team and for inclusion in a risk register update.

I'm happy to discuss the findings in the context of your current audit cycle or regulatory reporting obligations.

Regards,
DeCyberGuardian
Founder, AfriWealth Cyber Intelligence
afriwealthci.com

---

**PERSONALISATION GUIDE — COMPLIANCE TEMPLATE:**
- Reference BoG Cyber & Information Security Directive (2018, updated guidance)
- Reference NCA guidelines for telecoms
- Reference Ghana Data Protection Act 2012 (Act 843) for data handling obligations
- Frame findings as "audit-ready" — use language like risk register, control gap, assurance
- GHIPSS: mention PAPSS and regional payment system oversight

---

## Follow-Up Email (sent 5 business days after initial, if no response)

**Subject:** Re: SankofahEye findings on [domain] — following up

Hi [First Name],

Following up on the passive exposure report I sent across last week for [domain].

I wanted to flag one finding in particular that has a tight remediation window: [most urgent finding — e.g., certificate expiring in 26 days on gpinvite.ghipss.com / DMARC p=none on a domain handling student applications].

If this hasn't reached the right person internally, I'm happy to resend directly to your IT security lead or CISO.

The report and remediation plan are still attached.

DeCyberGuardian | AfriWealth Cyber Intelligence
afriwealthci.com

---

---

# PART 2 — PHYSICAL DROP-OFF CAMPAIGN

## Overview

The physical drop-off campaign complements email outreach with a tangible, high-quality intelligence product that lands on a desk rather than in a spam folder. In Ghana's institutional culture — where relationships and in-person presence carry real weight — a well-presented printed report signals credibility that a cold email alone cannot.

**Target institutions for Phase 1 drop-off:**
1. Ghana Interbank Payment and Settlement Systems (GHIPSS) — 67/100 HIGH
2. Ghana Scholarship Secretariat — 77/100 HIGH
3. Bank of Ghana — 54/100 MEDIUM (highest-value relationship)
4. MTN Ghana — 53/100 MEDIUM (largest telecom, MoMo exposure angle)
5. Ecobank Ghana — 20/100 LOW (lowest risk but good entry point — easier win)

---

## What to Print and Bring

For each target institution, prepare a physical pack containing:

**1. The SankofahEye PDF report** — printed in colour, bound or in a clear folder. The AfriWealth CI branding (teal/gold) should be visible on the cover. Print double-sided, stapled or comb-bound.

**2. A cover letter** — single page, on AfriWealth CI letterhead. Template below.

**3. A business card** — if you have them; if not, a printed contact card with your name, title, email, phone, and afriwealthci.com.

Pack these in a branded envelope or folder. Label the outside: **"AfriWealth Cyber Intelligence — Confidential Security Briefing — Attention: Head of IT Security / CISO"**

---

## Cover Letter Template (Reception Drop-Off)

---

**[DATE]**

**AfriWealth Cyber Intelligence**
Accra, Ghana | afriwealthci.com

**CONFIDENTIAL SECURITY BRIEFING**

**To:** Head of IT Security / Chief Information Security Officer
**From:** DeCyberGuardian, Founder — AfriWealth Cyber Intelligence
**Re:** Passive Exposure Assessment — [domain]

Dear Sir/Madam,

AfriWealth Cyber Intelligence has conducted a complimentary passive digital exposure assessment of [organisation]'s primary domain ([domain]).

This assessment uses only publicly available data sources — the same intelligence gathering techniques employed by threat actors conducting reconnaissance before targeting an organisation. No systems were accessed, no active scanning was performed.

The enclosed SankofahEye report documents [X] findings rated across a 0–100 risk scale. The overall risk score for [domain] is **[X]/100 — [RATING]**. Findings include [brief 2-line summary of top findings].

The report includes:
- MITRE ATT&CK technique mapping for each finding
- Attack scenario narratives explaining how each gap would be exploited
- A 3-track remediation action plan (72-hour / 30-day / 90-day)

This briefing is provided at no cost and with no obligation.

AfriWealth Cyber Intelligence provides ongoing passive exposure monitoring, executive-level reporting, and threat intelligence advisory services for Ghana's financial institutions, fintechs, and government agencies.

To discuss the findings or explore a monitoring engagement, please contact:

**DeCyberGuardian**
Founder, AfriWealth Cyber Intelligence
[email] | [phone] | afriwealthci.com

*Passive reconnaissance only — no active exploitation was performed. This report is intended solely for the named organisation and its authorised security personnel.*

---

## Walk-In Script (If You Get Past Reception)

**At reception:**
> "Good morning. My name is [Name], I'm the founder of AfriWealth Cyber Intelligence, a cybersecurity firm based in Accra. I've prepared a confidential security briefing for your Head of IT Security or CISO regarding your organisation's digital exposure. I have a report I'd like to leave for them — could you ensure it reaches them directly? I'll follow up by email."

**If they ask what it's about:**
> "It's a passive reconnaissance intelligence report. We conducted a non-invasive assessment of your domain using open-source intelligence — no systems were touched. The report identifies some security findings and provides a remediation plan. It's complimentary, no obligation."

**If you get connected to IT security directly (rare but happens):**
> "Thank you for seeing me. I run AfriWealth Cyber Intelligence — we provide passive exposure intelligence for Ghanaian financial institutions. I've already run a scan of your domain and the results are in this report. The overall risk score is [X]/100. There are [X] findings I'd like to walk you through — it takes about 10 minutes. Do you have a few minutes now, or should I schedule a proper briefing?"

**Key lines to have ready:**
- "This is passive only — we never touched your systems."
- "This is the same data a threat actor can gather for free in under an hour."
- "The remediation plan is already written. We just want the right people to see it."
- "We're not here to sell you anything today. We're here because this intelligence exists and you deserve to have it."

---

## Walk-In Meeting Script (If You Get a Sit-Down)

**Opening (60 seconds):**
> "I appreciate your time. I'm a CTI practitioner based in Ghana — I've spent [X] years in threat intelligence with a focus on West Africa's financial sector. I founded AfriWealth Cyber Intelligence because Ghanaian institutions face a real threat landscape that most Western security tools aren't built to understand. Last week I built and ran SankofahEye against several institutions in Ghana's financial and public sector — including yours."

**The hook (30 seconds):**
> "The scan is passive. No systems touched. But the findings are real. Your domain scored [X]/100. I want to show you three things that a threat actor could do with what's publicly visible on your infrastructure today."

**Walk through top 3 findings from the report** — show the printed pages, explain the attack scenario for each. Keep it to 5 minutes.

**The close:**
> "The remediation plan is in the report. Most of these findings are fixable — some in 72 hours. I'm not here to create panic. I'm here because this intelligence exists, and intelligence is only useful if it reaches the people who can act on it. If you'd like to discuss what ongoing monitoring looks like — where we run this scan continuously and flag new findings as they emerge — I'm happy to come back for a proper briefing."

---

## Campaign Logistics

**Timing:** Run the physical drop-offs the week after the LinkedIn series goes live. Your posts establish credibility before the envelope lands. If a security person at GHIPSS saw your LinkedIn post about their 67/100 score on Tuesday, your envelope on Friday lands very differently.

**Sequencing by risk score:** Start with GHIPSS (67) and Scholarships (77) — highest risk, strongest story. Bank of Ghana last — highest-value relationship, want to be sharpest when you walk in.

**Follow-up timing:** Email the named CISO/IT head 3 business days after drop-off. Subject: "Following up on the AfriWealth CI security briefing delivered to [organisation] on [date]."

**Track everything:** Keep a simple log — institution, date dropped, name left with at reception, follow-up email sent date, response received. This becomes your pipeline.

**What success looks like in Phase 1:**
- 1 meeting booked from 5 drop-offs = strong result
- 2+ meetings = exceptional
- Email replies from CISO-level contacts = warm leads for the next cycle
- Zero responses = you have a list of contacts to nurture via LinkedIn content

---

## AfriWealth CI Letterhead (for the cover letter)

Set up a simple Word/Google Doc letterhead with:
- AfriWealth CI name in teal (#008080) — top left or centred
- Tagline: *Passive Exposure Intelligence | Ghana & West Africa*
- Website: afriwealthci.com
- Email and phone number
- A thin gold (#FFD700) rule below the header

Keep it clean and professional. The report already has the branded design — the cover letter just needs to signal the same organisation.

---

*AfriWealth Cyber Intelligence | DeCyberGuardian | afriwealthci.com*
*Passive reconnaissance only — Not for public distribution*
