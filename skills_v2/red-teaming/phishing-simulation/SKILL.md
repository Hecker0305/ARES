---
name: phishing-simulation
description: >-
  Enterprise phishing simulation methodology covering campaign design, payload delivery, landing page setup,
  credential capture, awareness metrics, and actionable reporting for security awareness improvement.
domain: red-teaming
subdomain: phishing-simulation
tags: [phishing, red-team, social-engineering, awareness, simulation, email-security]
mitre_attack: [T1048, T1192, T1193, T1204, T1534, T1566]
nist_csf: [PR.AT-1, PR.AT-2, DE.CM-1, DE.CM-4, RS.MI-2]
d3fend: [D3-SEG, D3-PHISH, D3-URL, D3-EMAIL]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1, MAP-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during security awareness program testing, for measuring employee phishing susceptibility, when training new phishing simulation operators, and for validating email security controls.

## Prerequisites

- Phishing simulation platform (GoPhish, PhishMe, KnowBe4, M365 Attack Simulator)
- SMTP relay or email delivery service configured for simulation
- Landing page server for credential harvesting simulations
- Approved simulation targets list with management authorization
- Understanding of email authentication (SPF, DKIM, DMARC) for deliverability
- Python 3.10+ for custom phishing templates and automation

## Workflow

1. Define campaign scope: Select target groups (department, geography, role), simulation type (credential harvest, malware attachment, link), and duration
2. Design phishing template: Create authentic-looking email using company branding, relevant context (password reset, package delivery, document sharing), and convincing sender
3. Configure landing page: Set up credential harvesting page that mimics legitimate login page with SSL certificate
4. Configure SMTP delivery: Ensure proper email authentication (SPF, DKIM) for inbox delivery; avoid spam classification
5. Launch campaign: Schedule send with appropriate timing (avoid weekends, holidays, early mornings)
6. Monitor engagement: Track opens, clicks, credential submissions, and attachment launches in real-time
7. Analyze results: Segment by department, role, tenure, and prior training for vulnerability identification
8. Train affected users: Deliver immediate micro-training to users who clicked with educational content
9. Improve detection: Adjust email security filters based on observed delivery issues or spam classification
10. Report to management: Provide aggregated metrics, trends over time, improvement areas, and ROI of program

## Verification

- Campaign achieves meaningful click rate (target: 10-30% for initial campaigns, decreasing over time)
- Email deliverability to inbox is verified (> 95% to inbox, not spam)
- Landing page captures credentials and redirects to training page
- Phishing reporting button usage is tracked (target: > 20% of recipients report suspicious email)
- Repeat clickers are identified for targeted training
- Post-campaign awareness scores show improvement (re-test within 90 days)
- Campaign is fully authorized with signed ROE from management
