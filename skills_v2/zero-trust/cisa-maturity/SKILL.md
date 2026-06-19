---
name: cisa-maturity
description: >-
  CISA Zero Trust Maturity Model assessment and implementation roadmap covering the five pillars:
  Identity, Devices, Networks, Applications and Workloads, Data with cross-cutting capabilities.
domain: zero-trust
subdomain: cisa-maturity
tags: [cisa, zero-trust, maturity-model, identity, devices, networks, data, roadmap]
mitre_attack: [T1078, T1550]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.DS-1, PR.DS-5, PR.PT-1, de.cm-1]
d3fend: [D3-ZTA, D3-IAM, D3-EDR, D3-MICRO, D3-DPC]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2, MANAGE-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when developing a zero trust implementation roadmap aligned with CISA ZTMM, during agency or enterprise zero trust maturity assessment, for zero trust architecture planning, and when reporting zero trust progress to CISO/CIO.

## Prerequisites

- CISA Zero Trust Maturity Model v2.0 document (Oct 2023)
- Current state assessment of identity, device, network, application/workload, and data security
- Enterprise architecture documentation
- Security tool inventory
- Executive sponsorship for zero trust program
- Understanding of zero trust principles (never trust, always verify, least privilege)

## Workflow

1. Assess current maturity: Evaluate each of the 5 pillars (Identity, Devices, Networks, Applications & Workloads, Data) against CISA ZTMM levels (Traditional, Initial, Advanced, Optimal)
2. Score identity pillar: Assess identity governance, multi-factor authentication, privileged access management, and identity federation
3. Score devices pillar: Evaluate device inventory, compliance monitoring, endpoint detection, and mobile device management
4. Score networks pillar: Assess network segmentation, encryption, traffic management, and microsegmentation
5. Score application/workload pillar: Evaluate application access, least privilege, workload identity, and CI/CD security
6. Score data pillar: Assess data classification, encryption, data loss prevention, and data access governance
7. Identify maturity gaps: Compare current state to target state (Initial → Advanced → Optimal) for each pillar
8. Create implementation roadmap: Prioritize gaps by risk reduction and effort, create phased implementation plan (12/24/36 month)
9. Define metrics: Establish measurable maturity indicators for each pillar (e.g., MFA coverage %, segment coverage %, encrypted data %)
10. Report progress: Create executive dashboard showing maturity progression across pillars, milestone achievement, and risk reduction

## Verification

- Current maturity level is documented for each of the 5 CISA ZTMM pillars
- Implementation roadmap has defined milestones for 12, 24, and 36-month horizons
- Each milestone has defined success criteria and measurable KPIs
- MFA coverage target is 100% (all users, all applications)
- Device compliance covers 100% of managed devices
- Network segmentation covers all production workloads
- Data classification covers all data repositories
- Executive sponsorship is confirmed with regular maturity review cadence
- Maturity assessment is repeated annually to track progress
