---
name: bec-detection
description: >-
  Business Email Compromise detection methodology covering email header analysis, sender reputation,
  language analysis, anomaly detection, and automated phishing investigation workflows.
domain: phishing-defense
subdomain: bec-detection
tags: [bec, business-email-compromise, phishing, email-security, fraud-detection, spear-phishing]
mitre_attack: [T1192, T1193, T1534, T1566]
nist_csf: [DE.AE-2, DE.CM-1, DE.CM-4, DE.CM-7, PR.AT-1]
d3fend: [D3-SEG, D3-EMAIL, D3-URL, D3-AUTH]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during BEC incident investigations, when deploying email security controls against executive impersonation, for email fraud detection program implementation, and when training users to identify BEC attempts.

## Prerequisites

- Email security gateway (Proofpoint, Mimecast, M365 ATP, GWS, Abnormal Security)
- DMARC reporting system for domain authentication monitoring
- SIEM with email log ingestion
- Threat intelligence for known BEC infrastructure
- Executive contact list for impersonation detection
- Python 3.10+ for email header analysis and anomaly detection

## Workflow

1. Monitor email authentication: Track SPF, DKIM, and DMARC pass/fail rates per domain to identify spoofing attempts
2. Analyze email headers: Check `Reply-To`, `Return-Path`, `From`, and `Envelope-From` header inconsistencies
3. Detect display name spoofing: Flag emails where display name matches executive but email address domain is external
4. Analyze email content: Scan for urgent payment requests, gift card purchases, W-2 requests, and wire transfer language
5. Check sender behavior: Analyze sending patterns (time of day, volume, recipients) for anomalous email activity
6. Detect lateral phishing: Alert when compromised internal accounts send phishing emails to other employees
7. Monitor external forwarding: Detect rules created to auto-forward email to external addresses (data exfiltration)
8. Verify payment requests: Establish out-of-band verification for financial transaction requests via email
9. Analyze attachment URLs: Scan for lookalike domains (paypa1.com vs. paypal.com), typosquatting, and legitimate link manipulation
10. Create BEC detection rules: Deploy machine learning models or rule-based detection in email security gateway

## Verification

- Executive impersonation attempts are detected with > 95% accuracy
- DMARC-based authentication failures are quarantined or rejected
- Email header inconsistencies (mismatched From/Reply-To) trigger alerts
- Payment requests with changes to bank details require out-of-band verification
- Compromised internal accounts sending lateral phishing are rapidly detected
- External forwarding rules trigger immediate security review
- BEC detection false positive rate is < 1% to avoid alert fatigue
- All BEC incidents are documented with full email trace and investigation results
