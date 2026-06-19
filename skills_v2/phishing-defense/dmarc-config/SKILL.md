---
name: dmarc-config
description: >-
  DMARC configuration and management for email domain protection. Covers DMARC policy deployment,
  aggregate report analysis, forensic report handling, alignment modes, and policy progression from monitoring to enforcement.
domain: phishing-defense
subdomain: dmarc-config
tags: [dmarc, email-authentication, domain-protection, spoofing, phishing-defense, email-security]
mitre_attack: [T1566]
nist_csf: [PR.AC-1, PR.AC-3, PR.DS-2, de.cm-1]
d3fend: [D3-DMARC, D3-SPF, D3-DKIM, D3-SEG]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when deploying DMARC for organizational domains, during DMARC migration from policy monitoring to quarantine to reject, when troubleshooting email deliverability related to authentication, and during domain spoofing incident response.

## Prerequisites

- DNS management access for all sending domains
- DMARC report processing tool (URIports, DMARC Analyzer, dmarcian, Postmark)
- Email authentication already configured (SPF and DKIM)
- Understanding of DMARC alignment (strict vs relaxed) and policy options (none, quarantine, reject)
- Email delivery team coordination for policy changes
- Reporting email address for DMARC RUA and RUF reports

## Workflow

1. Audit current email authentication: Document SPF, DKIM, and any existing DMARC configuration for all domains
2. Configure DMARC monitoring: Set initial policy to `v=DMARC1; p=none; rua=mailto:dmarc@domain.com; ruf=mailto:forensic@domain.com; pct=100`
3. Collect aggregate reports: Configure DMARC report mailbox to receive XML aggregate reports from receivers (Google, Microsoft, Yahoo, etc.)
4. Analyze report data: Parse aggregate reports to identify all sources sending email for the domain, including authorized and unauthorized
5. Map legitimate senders: Identify and document all legitimate email sources (internal servers, ESPs, SaaS providers) with their SPF/DKIM status
6. Add missing sources: Update SPF records and DKIM configurations to cover all legitimate sources discovered in reports
7. Test policy progression: Move to `p=quarantine` for a subset of traffic (pct=5, 25, 50, 100) monitoring for delivery issues
8. Monitor forensic reports: Review RUF forensic reports for spoofing attempts and unauthorised email sources
9. Move to enforcement: Progress to `p=reject` after confirming 100% legitimate email passes authentication for 30+ days
10. Continuous monitoring: Monitor DMARC reports for new unauthorized sources, adjust SPF/DKIM as new services are added

## Verification

- DMARC policy is at `p=reject` for primary corporate domains
- Aggregate reports show >= 98% authentication pass rate for legitimate email
- SPF includes all authorized sending sources with `-all` mechanism
- DKIM signatures align with DMARC (d= matches From domain)
- No legitimate email is rejected due to DMARC after enforcement deployment
- Forensic reports are reviewed weekly for spoofing identification
- DMARC reporting address is monitored and reports are processed within 24 hours
- New services are added to SPF/DKIM before sending email from new domains
