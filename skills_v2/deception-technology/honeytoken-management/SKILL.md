---
name: honeytoken-management
description: >-
  Deception token management covering honeytoken deployment across directories, databases, cloud storage,
  API keys, and credentials. Includes token validation, alert triggers, and breach detection via token access.
domain: deception-technology
subdomain: honeytoken-management
tags: [honeytoken, deception-token, canary-token, breach-detection, decoy-credentials, fake-api-keys]
mitre_attack: [T1048, T1078, T1110, T1133]
nist_csf: [DE.CM-1, DE.CM-4, DE.CM-7, RS.AN-1, RS.MI-1]
d3fend: [D3-HT, D3-DEC, D3-CDR, D3-HN]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when deploying honeytokens to detect data breaches, for credential theft detection, for cloud credential misuse detection, and during insider threat monitoring programs.

## Prerequisites

- Honeytoken management platform (Thinkst CanaryTokens, BlueTalon, Custom deployment)
- File shares, databases, cloud storage (S3, Blob, GCS) for token placement
- API gateway or cloud access logs for token usage detection
- SIEM integration for token trigger alerting
- Python 3.10+ for custom honeytoken generation and deployment
- Understanding of attacker tools (Mimikatz, BloodHound) to set realistic deceptions

## Workflow

1. Identify token placement locations: Determine strategic locations for honeytokens (shared drives, databases, source code repos, cloud storage, email, active directory)
2. Generate honeytokens: Create realistic-looking tokens (fake credentials, API keys, database connection strings, cloud access keys, authentication tokens)
3. Deploy file-type tokens: Place token-containing files in strategic directories with realistic names (passwords.xlsx, aws_credentials.csv, production_db.txt)
4. Deploy credential tokens: Create fake AD accounts, service accounts, and application credentials for detection via credential theft tools
5. Deploy cloud tokens: Place fake cloud access keys in AWS S3 buckets, Azure Key Vault, and GCP storage with alerting on usage
6. Configure alert triggers: Set up alerting on any honeytoken access (read, modify, transfer, authentication attempt)
7. Integrate with SIEM: Forward honeytoken alerts to SIEM with high-priority correlation (honeytoken access = confirmed breach)
8. Deploy database tokens: Place fake rows in databases with realistic customer/employee/credential data
9. Monitor token usage: Review honeytoken access patterns, correlate with authentication logs for threat actor identification
10. Refresh tokens: Periodically rotate honeytokens (token accessed = burned), deploy new tokens in different locations

## Verification

- Honeytokens are undetectable to normal users (blend in with real data, not obvious decoys)
- Honeytoken access triggers alert within 1 minute
- No false positives from legitimate user activity (whitelisting functional)
- Honeytoken deployment covers all critical data repositories
- Honeytoken credentials are not valid for any real system
- Token alert includes full context (source IP, user, system, process, timestamp)
- Honeytoken program metrics are tracked (alerts, threat actor identification, time-to-detection improvement)
- Decoy tokens are regularly refreshed and redeployed as burned tokens are replaced
