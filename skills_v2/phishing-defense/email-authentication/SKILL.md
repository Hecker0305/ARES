---
name: email-authentication
description: >-
  Email authentication security methodology covering SPF, DKIM, and DMARC deployment and monitoring,
  BIMI configuration, MTA-STS, TLS-RPT, and email channel hardening against spoofing and phishing.
domain: phishing-defense
subdomain: email-authentication
tags: [spf, dkim, dmarc, bimile, mta-sts, email-security, phishing-defense, authentication]
mitre_attack: [T1192, T1566]
nist_csf: [PR.AC-1, PR.AC-3, PR.DS-2, de.cm-1, de.cm-4]
d3fend: [D3-SPF, D3-DKIM, D3-DMARC, D3-BIMI, D3-SEG]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when deploying email authentication for corporate domains, during DMARC migration from monitoring to enforcement, for phishing investigation involving domain spoofing, and during email security posture assessment.

## Prerequisites

- DNS management access for all email domains
- Email server/security gateway configuration access (Exchange, M365, GWS, Proofpoint, Mimecast)
- DMARC reporting analysis tools (DMARC Analyzer, URIports, dmarcian)
- Understanding of DNS record types (TXT, CNAME, SRV) and email flow (MX, MTA, delivery)
- Python 3.10+ for DMARC report parsing and analysis

## Workflow

1. Inventory email domains: List all domains that send or receive email for the organization (corporate, marketing, transactional, subdomains)
2. Configure SPF: Create DNS TXT record specifying authorized sending IPs and services: `v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all`
3. Configure DKIM: Generate public/private keypair, publish public key as DNS TXT record, enable DKIM signing on email servers
4. Publish DMARC policy (monitoring): Start with `p=none` and `rua=mailto:dmarc@domain.com` to receive aggregate reports
5. Analyze DMARC reports: Parse aggregate DMARC reports to identify all legitimate email sources and authentication failures
6. Identify spoofing attempts: Review forensic reports (ruf) for actual spoofing attempts and unauthorized email sources
7. Update SPF/DKIM: Add missing legitimate sources to SPF, fix any DKIM signing issues, address misconfigurations
8. Tighten DMARC policy: After monitoring phase (30+ days), move to `p=quarantine`, eventually `p=reject`
9. Deploy MTA-STS and TLS-RPT: Add MTA-STS policy for TLS enforcement and TLS reporting for delivery visibility
10. Enable BIMI: Publish BIMI DNS record with Verified Mark Certificate (VMC) for brand logo display in compliant email clients

## Verification

- SPF record covers all legitimate sending sources with `-all` (hard fail) for DMARC enforcement domains
- DKIM signatures validate correctly on all outgoing email (check with DKIM validator tools)
- DMARC policy is at `p=reject` for all primary email domains
- DMARC aggregate reports show >= 95% alignment pass rate
- MTA-STS policy enforces TLS for all inbound email
- BIMI brand logo displays in Gmail and Fastmail
- No legitimate email is quarantined or rejected due to email authentication
- DMARC reporting is monitored at least weekly for anomalies
