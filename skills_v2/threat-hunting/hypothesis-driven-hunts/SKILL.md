---
name: hypothesis-driven-hunts
description: >-
  Structured threat hunting methodology using hypothesis-driven approaches based on threat intelligence, 
  adversary emulation, and behavioral analytics. Translates TTPs into huntable data queries across SIEM, EDR, and logs.
domain: threat-hunting
subdomain: hypothesis-driven-hunts
tags: [threat-hunting, hypothesis, ttp, adversary-emulation, siem, edr, behavioral-analytics]
mitre_attack: [T1059, T1068, T1078, T1134, T1190, T1204, T1218, T1482, T1505, T1543, T1546, T1547, T1548, T1550, T1552, T1555, T1556, T1557, T1558, T1562, T1569, T1574]
nist_csf: [DE.AE-1, DE.AE-2, DE.AE-3, DE.AE-4, DE.CM-1, DE.CM-3, DE.CM-4, DE.CM-5, DE.CM-6, DE.CM-7, DE.DP-1, DE.DP-2, DE.DP-3, DE.DP-4, DE.DP-5]
d3fend: [D3-HN, D3-CDR, D3-EDR, D3-SIEM, D3-NDR, D3-BA]
nist_ai_rmf: [MEASURE-1.1, MEASURE-2.2, MEASURE-3.3, GOVERN-1.2, MAP-2.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when proactively hunting for unknown threats in the environment, after high-severity intelligence reports, during threat hunting cycles (weekly/monthly), when testing detection coverage against specific TTPs, or as part of purple team exercises to validate detection capabilities.

## Prerequisites

- Access to SIEM platform (Splunk, Elastic, Sentinel, Chronicle) with read permissions
- EDR platform access (CrowdStrike, Defender ATP, SentinelOne) for endpoint queries
- Python 3.10+ with pandas and numpy for data analysis
- Approved hunt plan with scope definitions (systems, time range, data sources)
- Knowledge of MITRE ATT&CK framework and specific TTPs being hunted
- Data retention of at least 30 days for historical analysis

## Workflow

1. Formulate hypothesis: Use threat intelligence to identify relevant TTPs targeting your industry. Document the hypothesis in a structured format: "If [adversary] then we should observe [behavior] in [data source]"
2. Identify data sources: Map required telemetry (process creation, network connections, registry changes, file events) to available data sources
3. Develop analytical query: Write detection logic in the SIEM query language (SPL, KQL, EQL) or Python for log analysis
4. Baseline normal behavior: Establish statistical baselines for the environment using 30+ days of historical data to reduce false positives
5. Execute hunt: Run the query across the specified time range and data scope
6. Analyze results: Triage results using a risk-based approach (prioritize [Enterprise] assets, critical systems)
7. Investigate anomalies: Deep-dive on suspicious results using EDR and additional data sources
8. Document findings: Capture detection rate, false positive rate, and new IOCs/TTPs observed
9. Create detection rule: Convert successful hunts into production detection rules with tuning
10. Update threat model: Refine adversary profiles and hypotheses based on hunt outcomes

## Verification

- Hypothesis is confirmed with at least one real detection or definitively refuted with documented evidence
- Hunt results are reproducible with the same query returning consistent results
- False positive rate is documented and below 10% for the specific hunt
- New detection rules have unit tests and are in staging
- Hunt coverage map is updated showing gaps filled by the hunt
- All findings are documented with full evidence chain in the case management system
