---
name: certificate-transparency
description: >-
  Certificate Transparency monitoring methodology for detecting unauthorized certificate issuance,
  domain monitoring, CT log auditing, and incident response for mis-issued certificates.
domain: cryptography
subdomain: certificate-transparency
tags: [certificate-transparency, ct-logs, monitoring, certificate-issuance, ssl-tls, pki]
mitre_attack: [T1553, T1583]
nist_csf: [DE.CM-1, DE.CM-4, ID.SC-2, PR.DS-1]
d3fend: [D3-CT, D3-CERT, D3-MON]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, DETECT-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when implementing certificate transparency monitoring for organizational domains, during incident response for suspected mis-issued certificates, for compliance with browser CT requirements, and when deploying automated certificate issuance monitoring.

## Prerequisites

- Certificate Transparency log monitoring tool (certspotter, crt.sh API, Facebook CT-monitor, Google CT API)
- Domain ownership verification for monitoring setup
- Python 3.10+ with requests and cryptography libraries for log parsing
- SIEM integration for CT alert correlation
- Understanding of X.509v3 certificate fields, SANs, CAs, and CT log structure
- Incident response process for unauthorized certificate handling

## Workflow

1. Register domain monitoring: Configure CT monitoring for all organizational domains and subdomains using certspotter or crt.sh API
2. Establish certificate baseline: Collect all currently valid certificates for monitored domains from CT logs
3. Monitor new certificate issuance: Poll CT logs (Google 'Argon', DigiCert 'Yeti', Cloudflare 'Nimbus') for new certificates matching domains
4. Analyze certificates: Check issuer CA, validity period, subject, SANs, key usage, and public key for anomalies
5. Alert on suspicious certificates: Trigger alerts for certificates issued by unauthorized CAs, unexpected subdomains, anomalous key sizes, or short validity
6. Validate certificate legitimacy: Cross-reference new certificates with internal certificate inventory and change management
7. Detect domain typo-squatting: Monitor for certificates issued to lookalike domains (g00gle.com instead of google.com)
8. Investigate mis-issuance: For unauthorized certificates, contact CA for revocation, conduct root cause analysis
9. Integrate with SIEM/SOAR: Create automated workflow for certificate alerts (ticket creation, analyst assignment)
10. Report CT metrics: Track certificate issuance volume, types, issuers, and anomaly detection rate monthly

## Verification

- All organizational domains are monitored in CT logs
- New certificate issuance is detected within 24 hours of log inclusion
- Unauthorized certificate issuance triggers immediate investigation and CA revocation request
- Certificate inventory is reconciled with CT log data monthly
- Typo-squatting domains are identified and mitigated
- CT log monitoring tool has 99.9% uptime and reliable alerting
- Certificate lifecycle (issuance, renewal, revocation) is documented and automated where possible
