---
name: alert-triage
description: >-
  Structured security alert triage methodology for SOC operations. Covers alert prioritization,
  initial investigation, false positive identification, escalation criteria, and documentation.
domain: security-operations
subdomain: alert-triage
tags: [soc, alert-triage, incident-response, false-positive, prioritization, escalation]
mitre_attack: [T1059, T1078, T1110, T1190, T1204, T1210, T1562]
nist_csf: [DE.AE-1, DE.AE-2, DE.AE-3, DE.CM-1, DE.DP-1, DE.DP-3, RS.AN-1, RS.AN-2]
d3fend: [D3-SIEM, D3-CORR, D3-ALR, D3-EDR]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, RESPOND-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during daily SOC operations for triaging incoming alerts, during shift handover for consistent alert handling, when training new SOC analysts, and when establishing or improving triage procedures.

## Prerequisites

- SIEM with alert queue management (Splunk ES, Elastic Security, Sentinel)
- SOAR platform for automated enrichment
- EDR console for endpoint investigation (CrowdStrike, Defender, SentinelOne)
- Threat intelligence platform for IOC lookups
- Runbooks for common alert types
- Ticketing system for tracking (ServiceNow, Jira, TheHive)

## Workflow

1. Initial triage: Review alert details (title, severity, timestamp, source, destination, user, system)
2. Enrich alert: Query SIEM for related events, check threat intel for IOCs, get asset criticality
3. Assess severity: Determine based on asset criticality, detection confidence, threat context, and environmental risk
4. Determine category: Classify as True Positive (TP), False Positive (FP), Benign True Positive, or Inconclusive
5. For FP: Create suppression rule, update whitelist, document reason, close alert
6. For TP/Benign: Determine if alert requires immediate escalation or can be batched
7. Escalate critical/high TP: Notify incident response team, provide initial findings, create incident ticket
8. Document findings: Record triage summary, evidence, decisions, and actions taken in alert notes
9. Update playbook: Propose improvements to alert tuning, enrichment, or triage guidance
10. Report metrics: Track mean time to triage, false positive rate, and analyst productivity

## Verification

- Alert is triaged within SLA: Critical < 15 min, High < 60 min, Medium < 4 hrs, Low < 24 hrs
- All triage actions are documented in alert notes with clear rationale
- False positive categorization is validated by peer review
- Escalated alerts include all relevant evidence and context
- Suppression rules are documented and reviewed for potential coverage gaps
- Triage metrics are tracked and reported weekly/daily
