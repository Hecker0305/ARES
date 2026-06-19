---
name: behavioral-analytics
description: >-
  User and Entity Behavioral Analytics (UEBA) for detecting insider threats, compromised accounts,
  and anomalous behavior patterns. Uses statistical modeling and machine learning baselines.
domain: threat-hunting
subdomain: behavioral-analytics
tags: [ueba, behavioral-analytics, insider-threat, anomaly-detection, machine-learning, user-behavior]
mitre_attack: [T1078, T1098, T1136, T1485, T1529, T1531]
nist_csf: [DE.AE-1, DE.AE-2, DE.AE-3, DE.CM-3, DE.CM-4, PR.AC-4]
d3fend: [D3-BA, D3-UEBA, D3-AAL]
nist_ai_rmf: [MEASURE-1.2, MEASURE-2.1, GOVERN-2.3, DETECT-3.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when deploying behavioral baselines for critical users and systems, during insider threat investigations, after detecting potential credential compromise, when deploying UEBA solutions in a new environment, and for continuous monitoring of privileged user activity.

## Prerequisites

- SIEM with UEBA capabilities or log aggregation to Python analytics pipeline
- Minimum 30 days of historical log data for baseline establishment
- Active Directory or identity provider logs (success/failed logins, privilege changes)
- VPN and remote access logs with geolocation data
- Data loss prevention (DLP) logs for data movement analysis
- Python 3.10+ with scikit-learn, pandas, numpy, and matplotlib
- Access to HR system for user role and department mapping

## Workflow

1. Data collection: Aggregate logs from identity provider, VPN, endpoints, DLP, and physical access systems into a unified data store
2. Feature engineering: Extract behavioral features per user/entity (login times, location, volume, peer group, resource access patterns)
3. Establish baseline: Compute rolling 30-day baseline for each behavioral feature (mean, std, percentiles)
4. Peer group analysis: Group users by department, role, and seniority for comparative behavioral analysis
5. Anomaly scoring: Apply statistical methods (z-score, MAD, IQR) and ML models (Isolation Forest, LOF) to score deviations
6. Risk aggregation: Combine anomaly scores across behavioral dimensions into a unified risk score
7. Tiered alerting: Configure risk thresholds (Low: 2-3 sigma, Medium: 3-4 sigma, High: 4+ sigma)
8. Investigation workflow: For high-risk alerts, correlate with other data sources (email, chat, HR records)
9. Feedback loop: Incorporate investigation outcomes to refine baselines and reduce false positives
10. Reporting: Generate daily/ weekly behavioral analytics summary for security team

## Verification

- Baselines reflect actual working patterns (business hours, typical locations, regular systems)
- Anomaly detection achieves >= 80% precision on test dataset of known malicious behaviors
- False positive rate is <= 5% after tuning (target: 1% for high-severity alerts)
- Peer groups are correctly assigned based on HR data
- Behavioral models are retrained weekly on rolling 30-day window
- All alerts are documented with risk scoring rationale and investigation results
