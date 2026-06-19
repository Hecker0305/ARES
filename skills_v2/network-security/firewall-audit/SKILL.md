---
name: firewall-audit
description: >-
  Network firewall rule audit and optimization including rule base review, shadowing detection, clean-up of stale objects,
  change management validation, and compliance verification against standards.
domain: network-security
subdomain: firewall-audit
tags: [firewall, audit, network-security, rule-review, compliance, access-lists]
mitre_attack: [T1021, T1043, T1048, T1090, T1572]
nist_csf: [PR.AC-4, PR.AC-5, PR.AC-6, PR.PT-3, PR.PT-4, DE.CM-1, ID.AM-5]
d3fend: [D3-FW, D3-ACL, D3-NACL, D3-SG, D3-ZTA]
nist_ai_rmf: [GOVERN-2.1, MEASURE-1.2, MAP-2.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during firewall rule base reviews (quarterly/annual), after network architecture changes, during compliance audits (PCI DSS, SOC 2), when investigating security incidents involving firewall bypass, and during firewall migration or consolidation projects.

## Prerequisites

- Firewall management console access (Check Point, Palo Alto, Fortinet, ASA, NSX)
- Rule analysis tools (Algosec, Tufin, SolarWinds, or custom scripting with Python)
- Network topology and zone definitions documentation
- Python 3.10+ with netmiko/paramiko for CLI-based firewall analysis
- Change management and ticket history
- Compliance requirements documentation (PCI DSS requirement 1, SOC 2 CC6)

## Workflow

1. Export rule base: Export all firewall rules from management console in structured format (CSV, XML, JSON)
2. Inventory objects: Document all network objects (IPs, services, applications, users, URL categories) with usage tracking
3. Analyze rule order: Verify rule ordering follows most-specific to most-general rule placement
4. Detect shadowing: Identify rules that are never reached due to preceding rules with broader scope
5. Find redundant rules: Locate rules with identical src/dst/service/action that can be consolidated
6. Identify overly permissive rules: Flag rules with `any/any` src, dst, or service for review
7. Review rule hits: Use hit counts to identify unused rules (zero hits in 90+ days)
8. Check compliance tagging: Verify rules are tagged with request ticket number, owner, and expiration date
9. Validate zone-based firewall: Confirm proper zone segmentation and inter-zone rule enforcement within and between zones
10. Generate audit report: Provide rule count, shadowing, redundancy, and cleanup recommendations

## Verification

- Rule base is reduced by >= 20% after cleanup (removing unused/redundant rules)
- No shadowed rules exist in the rule base
- All rules have documented owner, purpose, and change ticket reference
- Zero rules exist with both src and dst set to `any`
- Hit count analysis identifies and removes all rules with zero hits in 90+ days
- Rule change process is documented and followed for all modifications
