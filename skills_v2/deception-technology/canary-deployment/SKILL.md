---
name: canary-deployment
description: >-
  Canary token and canary device deployment for early breach detection. Covers canary token generation,
  network canary placement, cloud canary deployment, insider threat detection, and response automation.
domain: deception-technology
subdomain: canary-deployment
tags: [canary, canary-token, deception, early-warning, breach-detection, canarytokens, thinkst]
mitre_attack: [T1048, T1078, T1090, T1133, T1190]
nist_csf: [DE.CM-1, DE.CM-4, DE.CM-7, RS.AN-1]
d3fend: [D3-HN, D3-DEC, D3-HT, D3-CD]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during deception technology deployment for early breach detection, for canary token deployment in sensitive environments, during insider threat detection programs, and when implementing early warning systems for network breaches.

## Prerequisites

- Canary token management (Thinkst CanaryTokens, Canarytokens.org, or custom)
- Network canary devices (Thinkst Canary, Raspberry Pi with canary software)
- Cloud infrastructure (AWS, Azure, GCP) for cloud canary deployment
- SIEM integration for canary trigger alerting
- Python 3.10+ for custom canary tooling
- SOAR platform for automated response to canary triggers
- Rules of Engagement for canary deployment in production

## Workflow

1. Identify deployment zones: Determine strategic locations for canary detection (network segments, cloud accounts, CI/CD pipeline, remote access endpoints)
2. Deploy network canaries: Deploy Thinkst Canary devices or Raspberry Pi canaries in critical network segments with decoy services (DNS, HTTP, SMB, RDP, SSH)
3. Generate canary tokens: Create triggers using Canarytokens.org or Thinkst tokens: DNS token, web bug token, AWS key token, SQL Server honeytoken, API key token
4. Deploy file-based canaries: Place canary token files (.pdf, .docx, .xlsx) in strategic folders with embedded web bug triggers
5. Deploy cloud canaries: Create fake cloud resources (S3 buckets, Lambda functions, API endpoints) with alerting on access
6. Integrate alerts to SIEM/SOAR: Configure canary triggers to generate high-priority incidents in SIEM
7. Define response playbook: Create automated response for canary triggers (isolate network segment, disable IAM user, alert SOC)
8. Test canary triggers: Verify each canary trigger generates alert with correct context (source IP, time, user agent)
9. Monitor and tune: Review canary alert frequency, tune out false positives, adjust canary placement
10. Expand coverage: Deploy additional canaries based on threat intelligence and incident response findings

## Verification

- All canary tokens generate alerts within 60 seconds of trigger
- Network canaries show as real devices in network scans (not obviously fake)
- File-based canaries are accessible through normal file share access but trigger when opened
- Cloud canaries appear in resource listings but have no production impact
- SIEM alerts for canary triggers are high-priority and cannot be tuned out accidentally
- Canary deployment covers all critical network segments and sensitive data zones
- Automated response playbook is tested and functional for each canary type
- Canary inventory is maintained with token location, type, and trigger history
