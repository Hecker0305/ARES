---
name: physical-security
description: >-
  Physical security assessment methodology for red team operations covering tailgating, lock picking,
  badge cloning, RFID attacks, facility access control bypass, and social engineering of physical security.
domain: red-teaming
subdomain: physical-security
tags: [physical-security, red-team, tailgating, lock-picking, rfid, access-control, social-engineering]
mitre_attack: [T1207, T1553]
nist_csf: [PR.AC-2, PR.PT-2, de.cm-1, de.cm-3]
d3fend: [D3-ACS, D3-PHY, D3-CCTV, D3-ID]
nist_ai_rmf: [GOVERN-2.1, MEASURE-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during red team operations requiring facility access, during physical security audits, for testing security guard response and badge access controls, and when assessing surveillance coverage.

## Prerequisites

- Lock pick set (tension wrench, rake, hook picks) for pin tumbler locks
- RFID cloning hardware (Proxmark3, Flipper Zero, iCopy-X)
- Social engineering pretext for physical access attempts
- Understanding of facility layouts (entrances, guard stations, badge readers)
- Technical surveillance detection tools (RF detector, camera finder)
- Rules of Engagement clearly defining allowed physical access methods

## Workflow

1. Reconnaissance facility: Observe entry points, guard presence, badge reader types, camera placement, and employee traffic patterns
2. Test badge cloning: Capture RFID card data using Proxmark3 at range to clone access cards
3. Attempt tailgating: Follow authorized personnel through secure doors with plausible pretext (hands full, forgot badge, smoking break)
4. Test perimeter security: Check fence integrity, locked gates, loading dock access, and underground parking access
5. Attempt lock picking: Test pin tumbler, wafer, and tubular locks on server rooms, IDF closets, and executive offices
6. Test electronic access: Check keypad access codes (shoulder surfing, default codes, worn keys), intercom bypass
7. Assess surveillance: Identify camera blind spots, recording duration, and monitoring center response time
8. Test security guard response: Conduct test scenarios to measure detection and response times
9. Document physical findings: Map access controls, vulnerabilities, and successful bypass methods
10. Report physical risk: Compile findings with criticality ratings, remediation recommendations, and timeframes

## Verification

- Physical access to target area is achieved (reception, office floor, server room, wiring closet)
- Badge cloning captures valid credentials and produces working clone
- Tailgating success rate is documented (attempts vs successes)
- Lock picking success is timed (under 5 minutes for standard locks)
- Security guard response time is measured (target: < 2 minutes for active breach)
- Cameras are identified with blind spots documented
- Findings are reported with actionable remediation for each control gap
