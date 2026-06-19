---
name: iso27001-audit
description: >-
  ISO 27001 ISMS audit methodology covering Annex A control review, Statement of Applicability analysis,
  risk assessment implementation, internal audit procedures, and certification readiness evaluation.
domain: compliance-governance
subdomain: iso27001-audit
tags: [iso27001, isms, audit, compliance, annex-a, soa, risk-assessment, certification]
mitre_attack: [T1078, T1110, T1562]
nist_csf: [ID.GV-1, ID.RA-1, ID.RA-2, ID.RA-3, PR.AC-1, PR.AC-3, PR.AC-4, PR.DS-1, PR.IP-1, de.cm-1]
d3fend: [D3-IAM, D3-VM, D3-AUDIT, D3-PVM, D3-RM]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2, MANAGE-1.1, MANAGE-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during ISO 27001 implementation and certification, for ISMS audit preparation, during internal audit program execution, and when preparing Statement of Applicability (SoA) and risk treatment plans.

## Prerequisites

- ISO/IEC 27001:2022 standard and ISO 27002:2022 control guidance
- GRC platform for risk management and control tracking
- ISMS documentation (scope, policy, risk assessment, SoA, risk treatment plan)
- Internal audit team or qualified auditors
- Understanding of ISMS clauses 4.1-10.2 (Context, Leadership, Planning, Support, Operation, Evaluation, Improvement)
- Training program for ISMS awareness

## Workflow

1. Establish ISMS scope: Define organizational context, interested parties, and ISMS boundaries (Clause 4)
2. Perform risk assessment: Identify assets, threats, vulnerabilities, and impacts; assess inherent and residual risk
3. Create Statement of Applicability: Evaluate all 93 Annex A controls for applicability, document justification for inclusions/exclusions
4. Develop risk treatment plan: Define treatment options (mitigate, transfer, accept, avoid) for each risk, assign control owners
5. Implement controls: Deploy applicable Annex A controls (technical, organizational, physical, legal)
6. Document ISMS: Create mandatory documentation (ISMS policy, risk assessment report, SoA, risk treatment plan, audit program)
7. Train personnel: Conduct ISMS awareness training for all employees, specialized training for control owners
8. Conduct internal audit: Schedule and execute internal audits against ISO 27001 clauses and Annex A controls
9. Perform management review: Present ISMS performance to management, review effectiveness, and identify improvements
10. Prepare for certification: Address internal audit findings, conduct pre-certification gap assessment, coordinate with certification body

## Verification

- ISMS scope is defined and documented with organizational context
- Risk assessment covers all identified risks with assigned owners
- SoA includes all 93 Annex A controls with justification for each
- Risk treatment plan has defined owners, timelines, and resources
- Internal audit findings are tracked to closure with evidence
- Management review minutes document ISMS performance decisions
- Corrective actions are implemented for identified non-conformities
- Pre-certification gap assessment shows readiness for Stage 1 and Stage 2 audits
