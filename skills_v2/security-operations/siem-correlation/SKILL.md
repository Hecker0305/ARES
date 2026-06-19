---
name: siem-correlation
description: >-
  SIEM correlation rule development, tuning, and management across Splunk, Elastic Security,
  Microsoft Sentinel, and QRadar platforms for detecting multi-stage attacks.
domain: security-operations
subdomain: siem-correlation
tags: [siem, correlation, detection, splunk, elastic, sentinel, qradar, use-case]
mitre_attack: [T1059, T1078, T1110, T1133, T1190, T1204, T1210, T1530, T1562]
nist_csf: [DE.AE-1, DE.AE-2, DE.AE-3, DE.AE-4, DE.CM-1, DE.CM-3, DE.CM-4, DE.CM-6, DE.DP-1, DE.DP-2]
d3fend: [D3-SIEM, D3-CORR, D3-ALR, D3-EDR, D3-NDR]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, DETECT-3.1, MEASURE-1.2, MONITOR-1.1, MONITOR-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when building new detection use cases in SIEM, during investigation of multi-stage attacks requiring log correlation, when tuning detection rules for false positive reduction, and during SIEM platform migration.

## Prerequisites

- SIEM platform with correlation capabilities (Splunk, Elastic, Sentinel, QRadar, Chronicle)
- Log sources ingested: Windows Event Logs, Sysmon, firewall, proxy, DNS, EDR, cloud audit logs
- Python 3.10+ for custom detection logic and automation
- MITRE ATT&CK framework for mapping detections to TTPs
- SOAR platform for response automation integration
- Log search query languages (SPL, KQL, EQL, Kusto)

## Workflow

1. Identify detection use case: Document the specific attack scenario, affected TTP, data sources, and response actions
2. Define detection logic: Create correlation rules that chain multiple events across different data sources
3. Write SIEM query: Implement logic using platform-specific search language (SPL, KQL, EQL, KQL/Kusto)
4. Tune threshold: Determine alert threshold (count, time window, entity aggregation) using baseline traffic patterns
5. Test against known attacks: Validate detection against historical attacks (red team exercises, known compromises)
6. Deploy in test mode: Run in monitoring-only mode for 14+ days to observe false positive rate
7. Adjust tuning parameters: Modify thresholds, add whitelists, adjust time windows based on FP analysis
8. Implement response: Create SOAR playbook triggered by correlation rule for automated triage and response
9. Document rule: Record rule purpose, logic, data sources, tuning parameters, and false positive handling
10. Review and update: Monthly review of hit rates, false positives, and detection coverage gaps

## Verification

- Detection rule fires correctly on test dataset with labeled attack events
- False positive rate is < 5% after tuning period
- Response time from attack to alert is < 1 minute
- Rule covers the targeted TTP with supporting evidence chain
- SOAR playbook executes correctly when alert fires
- Rule performance does not impact SIEM query latency (runtime < 30s per search)
