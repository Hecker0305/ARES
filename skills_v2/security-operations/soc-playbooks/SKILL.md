---
name: soc-playbooks
description: >-
  Security orchestration and automated response (SOAR) playbook development methodology covering
  automation of common SOC workflows, enrichment, containment actions, and reporting.
domain: security-operations
subdomain: soc-playbooks
tags: [soar, playbooks, automation, soc, incident-response, enrichment, containment]
mitre_attack: [T1078, T1110, T1133, T1204, T1562]
nist_csf: [DE.AE-1, DE.CM-1, DE.DP-1, RS.AN-1, RS.CO-1, RS.MI-1, RS.MI-2, RS.MI-3, RS.RP-1]
d3fend: [D3-SOAR, D3-ORC, D3-ALR, D3-EDR, D3-SIEM]
nist_ai_rmf: [DETECT-1.2, RESPOND-1.1, RESPOND-2.2, GOVERN-2.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when automating repetitive SOC tasks, during SOAR platform implementation, when developing incident response automation for common threat types, and when creating standardized response procedures.

## Prerequisites

- SOAR platform access (Splunk SOAR, Palo Alto XSOAR, Microsoft Sentinel, Swimlane)
- SIEM integration configured with SOAR platform
- EDR API access for automated containment
- IT ticketing system for case management
- Threat intel platform for automated enrichment
- Python 3.10+ for custom SOAR actions
- Understanding of API authentication methods (OAuth2, API keys, basic auth)

## Workflow

1. Identify automatable workflow: Choose high-volume, low-complexity alerts with clear decision trees
2. Document process steps: Create flowchart of triage, enrichment, containment, and notification steps
3. Configure trigger: Define alert conditions that initiate the playbook (SIEM correlation rule, manual trigger, API)
4. Build enrichment actions: Add automated IOC lookups (VirusTotal, AbuseIPDB, WHOIS), asset criticality queries
5. Implement decision logic: Create branching based on enrichment results (malicious IOC -> contain, unknown -> escalate)
6. Design containment actions: Define automated containment steps (block IP in firewall, isolate endpoint in EDR, disable user in AD)
7. Add notification steps: Configure email, Slack, Teams or PagerDuty notifications with playbook summary
8. Create case management: Generate ticket with all playbook steps, enrichment results, and actions taken
9. Test playbook: Execute in test mode with historical alerts to validate decision logic and actions
10. Deploy with safeguards: Run in semi-automated mode (requires manual approval for destructive actions) initially

## Verification

- Playbook completes its execution path within SLA (target: < 5 minutes for automated triage)
- Enrichment sources respond successfully and results are captured in case notes
- Containment actions (when executed) are verified (endpoint isolated, IP blocked, user disabled)
- Notifications are delivered with correct information to appropriate parties
- Playbook handles error conditions gracefully (service unavailable, API failure)
- False positive rate of automated containment actions is 0% (manual approval for destructive actions)
