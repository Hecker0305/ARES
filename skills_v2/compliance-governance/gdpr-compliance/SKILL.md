---
name: gdpr-compliance
description: >-
  GDPR compliance methodology covering data protection impact assessments, data subject rights handling,
  data inventory mapping, breach notification procedures, and Data Protection Officer engagement.
domain: compliance-governance
subdomain: gdpr-compliance
tags: [gdpr, data-protection, privacy, dpia, data-subject-rights, pii, compliance]
mitre_attack: [T1005, T1114, T1530, T1560]
nist_csf: [ID.GV-1, ID.GV-3, PR.DS-1, PR.DS-2, PR.IP-3, de.cm-1, de.cm-4, RS.AN-1]
d3fend: [D3-DS, D3-DL, D3-DM, D3-PIA]
nist_ai_rmf: [GOVERN-1.1, GOVERN-2.2, MEASURE-1.2, MAP-1.1, MAP-2.1, MANAGE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during GDPR compliance program implementation, for Data Protection Impact Assessments (DPIA), when developing data subject rights handling procedures, during breach notification preparation, and for data inventory mapping exercises.

## Prerequisites

- GDPR regulation text and EDPB guidelines
- Data mapping and classification tools (egnyte, BigID, OneTrust, Securiti)
- Records of Processing Activities (ROPA) documentation
- Data Protection Officer (DPO) designated
- Privacy legal counsel engagement
- Data subject request management system
- Understanding of data processing activities, legal bases, and cross-border data transfers

## Workflow

1. Conduct data inventory: Map all personal data processing activities, data flows, data retention periods, and third-party data sharing across the organization
2. Create ROPA: Document Records of Processing Activities per Article 30 (controller and processor ROPA)
3. Verify legal basis: Validate legal basis for each processing activity (consent, legitimate interest, contractual necessity, legal obligation)
4. Perform DPIA: Conduct Data Protection Impact Assessment for high-risk processing activities (Article 35)
5. Implement data subject rights: Establish procedures for DSARs (Data Subject Access Requests), rectification, erasure, portability, restriction, and objection
6. Manage consent: Implement consent management platform with granular consent collection, withdrawal, and record-keeping
7. Ensure data minimization: Review data collection practices to ensure only necessary personal data is collected and retained
8. Implement breach notification: Develop 72-hour breach notification procedure for supervisory authority and affected data subjects
9. Manage cross-border transfers: Verify adequate safeguards for international data transfers (SCCs, BCRs, adequacy decisions, TIA)
10. Monitor compliance: Track KPIs (DSAR response time, breach notification time, DPIA completion rate), provide privacy training

## Verification

- Data inventory covers all personal data processing activities (completeness >= 95%)
- ROPA is documented and current (updated within last 6 months)
- DPIAs are completed for all high-risk processing activities
- DSAR response time meets 30-day SLA (extendable by 2 months for complex requests)
- Consent records show granular opt-in with withdrawal capability
- Breach notification procedure is tested with tabletop exercise
- SCCs/BCRs are in place for all cross-border data transfers
- Privacy notice is current and covers all required GDPR Articles 13/14 information
- Data retention schedules are implemented and enforced
