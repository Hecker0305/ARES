---
name: ir-playbooks
description: >-
  Incident response playbook development covering playbook design patterns, decision trees, automated actions,
  stakeholder communication templates, and continuous improvement through after-action reviews.
domain: incident-response
subdomain: ir-playbooks
tags: [incident-response, playbook, runbook, automation, ir-plan, playbook-development]
mitre_attack: [T1078, T1110, T1190, T1204, T1485, T1486, T1562]
nist_csf: [RS.AN-1, RS.AN-5, RS.CO-1, RS.CO-2, RS.MI-1, RS.MI-2, RS.MI-3, RS.RP-1, RS.IM-1, RS.IM-2]
d3fend: [D3-ORC, D3-SOAR, D3-PB]
nist_ai_rmf: [GOVERN-1.1, RESPOND-1.1, RESPOND-2.2, MANAGE-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when developing new incident response playbooks, during SOAR platform implementation, for incident response program maturity improvement, after significant incidents that reveal process gaps, and during team training exercises.

## Prerequisites

- Incident response framework (NIST SP 800-61, SANS PICERL)
- SOAR platform for playbook automation (Splunk SOAR, XSOAR, Sentinel)
- Stakeholder contact list with communication preferences
- Playbook repository (Git, Wiki, SOAR Playbook library)
- SIEM and EDR API access for automated enrichment
- Python 3.10+ for custom playbook actions and integrations

## Workflow

1. Identify incident scenario: Choose a specific, repeatable incident type (phishing, malware, brute force, data leak, insider threat)
2. Define trigger conditions: Specify exactly which alerts or conditions initiate the playbook with priority and SLAs
3. Create decision tree: Map out triage decisions, enrichment steps, containment options, and escalation criteria
4. Design automated steps: Identify actions that can be automated (IOC enrichment, user lookup, asset criticality check)
5. Define manual steps: Document actions requiring human judgment (severity determination, client communication)
6. Create communication templates: Draft stakeholder notification templates for different incident phases and audiences
7. Implement technical actions: Connect to SIEM, EDR, firewall APIs for automated enrichment and containment (via SOAR)
8. Test playbook: Walk through with tabletop exercise using historical incident data to validate decision logic
9. Train team: Conduct training session with SOC analysts on playbook usage and decision points
10. Review and update: After each use, conduct after-action review and update playbook based on lessons learned

## Verification

- Playbook covers the complete incident lifecycle (detection → triage → containment → eradication → recovery → post-mortem)
- Decision tree covers all known branching scenarios with clear criteria
- Automated steps complete within SLA timeframes (enrichment < 2 minutes, containment < 5 minutes)
- Communication templates are pre-approved by legal and management
- Playbook is tested at least quarterly with tabletop exercises
- Post-incident updates are applied within 2 weeks of incident closure
- Playbook version control is maintained (Git or equivalent)
