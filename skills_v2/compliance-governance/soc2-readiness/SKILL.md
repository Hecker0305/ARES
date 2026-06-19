---
name: soc2-readiness
description: >-
  SOC 2 Type II readiness assessment and implementation covering trust services criteria, control design,
  evidence collection, policy development, and audit preparation for SOC 2 compliance.
domain: compliance-governance
subdomain: soc2-readiness
tags: [soc2, compliance, audit, trust-services, controls, evidence, readiness]
mitre_attack: [T1078, T1110, T1562]
nist_csf: [ID.GV-1, ID.GV-2, ID.GV-3, PR.AC-1, PR.AC-3, PR.AC-4, PR.DS-1, PR.DS-2, PR.IP-1, PR.IP-3, de.cm-1]
d3fend: [D3-IAM, D3-VM, D3-PVM, D3-AUDIT]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2, MANAGE-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during SOC 2 readiness assessment, when preparing for Type II audit, for SOC 2 control design and implementation, and when developing SOC 2 evidence collection and monitoring processes.

## Prerequisites

- SOC 2 Trust Services Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy)
- AICPA SOC 2 Guide (TSP Section 100)
- GRC platform or evidence management system (AuditBoard, OneTrust, Vanta, Drata, Secureframe)
- Understanding of control objectives and control activities
- Audit management and coordination experience
- Policy and procedure documentation standards

## Workflow

1. Define scope: Select Trust Services Criteria (Security is mandatory; optional: Availability, Confidentiality, Processing Integrity, Privacy), define system description boundaries
2. Identify in-scope systems: Document all systems, data flows, infrastructure, and controls that support the defined trust services criteria
3. Perform readiness assessment: Evaluate current control environment against SOC 2 criteria using control matrix
4. Design control activities: Document control activities for each criteria (policy, procedure, monitoring, and evidence)
5. Develop control documentation: Create policies, standards, procedures, and work instructions for control operation
6. Implement controls: Deploy technical and administrative controls mapped to SOC 2 criteria
7. Collect evidence: Gather evidence of control operation (system reports, access reviews, change tickets, monitoring dashboards)
8. Establish monitoring: Set up ongoing control monitoring with defined KPIs and alerting for control failures
9. Conduct internal testing: Test control design and operating effectiveness before external audit
10. Prepare for audit: Create audit evidence repository, train control owners, conduct walkthroughs with internal team

## Verification

- All SOC 2 Trust Services Criteria have corresponding control activities documented
- Control evidence is collected for each criterion (at minimum 3 months for Type II)
- Gap assessment shows < 5 control deficiencies before audit engagement
- Control monitoring is operational with alerts for control failures
- Internal audit testing shows control operating effectiveness >= 95%
- Audit evidence repository is organized and accessible to auditors
- Control owners are trained on control documentation and evidence collection
- Bridge letter from last SOC 2 report is available if applicable
