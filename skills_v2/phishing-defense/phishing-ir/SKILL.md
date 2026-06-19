---
name: phishing-ir
description: >-
  Phishing incident response methodology covering phishing email triage, URL and attachment analysis,
  mailbox remediation, user reporting workflows, and threat intelligence extraction from phishing campaigns.
domain: phishing-defense
subdomain: phishing-incident-response
tags: [phishing, incident-response, email-security, phish-analysis, threat-intel, mail-remediation]
mitre_attack: [T1566, T1192, T1193, T1598]
nist_csf: [DE.CM-4, DE.CM-7, PR.AC-3, RS.AN-1, RS.MI-1, RS.MI-3]
d3fend: [D3-EMA, D3-URL, D3-HA, D3-MS]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, RESPOND-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during active phishing incident response, for phishing campaign investigation and remediation, when analyzing suspicious emails reported by users, and for extracting threat intelligence from phishing attacks.

## Prerequisites

- Email security gateway (M365 Defender, Proofpoint, Mimecast, Cisco ESA) access
- Sandbox environment for URL and attachment analysis (any.run, Joe Sandbox, Cuckoo)
- SIEM/SOAR platform for alert correlation and automated response
- Phishing analysis tools (PhishTool, URLScan.io, VirusTotal, InQuest)
- Mailbox access for remediation (Exchange Admin Center, Graph API)
- Python 3.10+ for automated analysis and IOC extraction
- User reporting integration (PhishAlarm, Outlook Report Message, KnowBe4)

## Workflow

1. Triage phishing report: Verify email metadata (SPF, DKIM, DMARC), analyze headers, check sender reputation and domain age
2. Extract IOCs: Pull URLs, attachments, sender addresses, reply-to addresses, and email subjects from reported phishing
3. Analyze URLs: Submit URLs to URLScan.io/VirusTotal, check for phishing pages, capture landing page screenshots
4. Analyze attachments: Submit attachments to sandbox for dynamic analysis, extract embedded URLs and macros
5. Determine scope: Search mailboxes for email delivery (Get-MessageTrace, Graph API), identify all recipients
6. Contain threat: Remove email from all mailboxes (hard delete), block sender domain/IP, delete from quarantine
7. Block indicators: Add URLs and domains to blocklist, update email gateway rules, block file hashes in EDR
8. User notification: Send targeted notification to affected users, provide phishing awareness guidance
9. Extract threat intelligence: Identify phishing kit, capture C2 infrastructure, identify TTPs, update TI platform
10. Post-incident review: Document findings, update detection rules, improve user reporting, create detection signatures

## Verification

- All instances of phishing email are removed from mailboxes (confirmed via search)
- Blocked indicators are tested and confirmed blocked across email and web gateways
- No users entered credentials or executed attachments (confirmed via authentication logs and EDR)
- Affected users acknowledged notification and phishing awareness guidance
- Threat intelligence extracted is submitted to TI platform
- Detection rules updated to catch similar phishing campaigns
- Incident report completed with timeline, IOCs, TTPs, and remediation actions
- User reporting rate and mean-time-to-report are tracked for improvement
