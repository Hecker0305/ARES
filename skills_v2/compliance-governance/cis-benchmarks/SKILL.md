---
name: cis-benchmarks
description: >-
  CIS benchmark implementation and auditing methodology covering automated assessment, remediation scripting,
  exception management, waiver tracking, and continuous compliance monitoring across OS, cloud, and applications.
domain: compliance-governance
subdomain: cis-benchmarks
tags: [cis-benchmarks, compliance, hardening, benchmarks, scoring-tool, security-configuration]
mitre_attack: [T1190, T1204, T1562]
nist_csf: [ID.RA-1, ID.RA-2, PR.AC-1, PR.AC-4, PR.DS-1, PR.IP-1, de.cm-1, de.cm-3, de.cm-4]
d3fend: [D3-CB, D3-VM, D3-PVM, D3-IAV]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2, MANAGE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when implementing CIS benchmarks for system hardening, during compliance auditing against CIS controls, for CIS scoring tool deployment, and when integrating CIS benchmarks into configuration management.

## Prerequisites

- CIS benchmark PDFs for target platforms (CIS Downloads or subscription)
- CIS-CAT Pro or CIS-CAT Lite Assessor for automated assessment
- Infrastructure access (OS, cloud console, application config) for remediation
- Configuration management tooling (Ansible, Puppet, Chef, DSC) for automation
- Python 3.10+ for custom remediation scripting
- Exception management process for benchmark deviations

## Workflow

1. Select applicable benchmarks: Identify relevant CIS Benchmarks for the environment (OS: Windows Server 2022, Linux RHEL 9, Cloud: AWS, Azure, GCP)
2. Download and configure CIS-CAT: Install CIS-CAT Assessor, configure profiles (Level 1 or Level 2) based on system classification
3. Run initial assessment: Execute CIS-CAT against target systems using `./Assessor-CLI.sh -i -b benchmarks/<benchmark>.xml -p "<profile>"`
4. Analyze results: Parse assessment results to identify failed recommendations by severity (Not Scored, Low, Medium, High, Critical)
5. Prioritize remediation: Address Critical and High failures first, then Level 1 vs Level 2 recommendations
6. Implement automated remediation: Create Ansible Playbooks or PowerShell DSC configurations for repeatable hardening
7. Test remediation: Apply hardening to test systems first, validate no production impact before production deployment
8. Manage exceptions: Document business-justified exceptions with risk acceptance for non-compliant recommendations
9. Establish continuous monitoring: Schedule recurring CIS-CAT assessments (weekly critical systems, monthly all systems)
10. Report compliance score: Track CIS compliance score over time, report to management with trend analysis

## Verification

- CIS compliance score is >= 90% for Level 1 benchmarks on all production systems
- Automated remediation is deployed via configuration management (no manual hardening)
- All high/critical CIS recommendations are implemented or documented with exception
- CIS-CAT assessment runs are scheduled and automated
- Compliance score trend shows continuous improvement (no regression)
- Exception register is maintained with risk acceptance for each deviation
- CIS benchmarks are updated annually with new recommendations reviewed
- Scoring tool configuration matches target environment profile
