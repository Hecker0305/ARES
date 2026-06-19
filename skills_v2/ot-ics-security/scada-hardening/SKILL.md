---
name: scada-hardening
description: >-
  SCADA system hardening guide covering HMI security, RTU/PLC access controls, engineering workstation
  lockdown, network segmentation, remote access security, and patch management for industrial systems.
domain: ot-ics-security
subdomain: scada-hardening
tags: [scada, hardening, hmi, plc, rtu, industrial-security, ot-security, ics]
mitre_attack: [T0816, T0822, T0823, T0835, T0836, T0839, T0855]
nist_csf: [PR.AC-1, PR.AC-4, PR.AC-5, PR.DS-1, PR.DS-5, PR.PT-1, PR.PT-3, DE.CM-1]
d3fend: [D3-FW, D3-SG, D3-IAM, D3-PAM, D3-VM]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.2, MAP-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during SCADA security assessments, engineering workstation lockdown, ICS network segmentation projects, remote access implementation for OT, and during compliance audits (IEC 62443, NERC CIP).

## Prerequisites

- OT network diagram and asset inventory
- SCADA system documentation (vendors: Siemens, ABB, Schneider, Rockwell, GE)
- Access to engineering workstations for hardening
- Patch management system tested for ICS compatibility
- Remote access solution (jump box, VPN, out-of-band modem)
- Multi-factor authentication for OT access

## Workflow

1. Asset inventory: Document all OT devices (HMI, PLC, RTU, IED, historian, engineering workstation)
2. Network segmentation: Deploy OT-specific firewalls (Tofino, Hirschmann, MGuard) between IT/OT and OT zones
3. HMI security: Lock down HMI workstations with application whitelisting, disable USB, remove admin rights
4. PLC/RTU access: Change default passwords, disable unused protocols, restrict programming access to engineering ports
5. Engineering workstation: Implement full disk encryption, local security policies, application control, disable internet access
6. Remote access: Deploy multi-factor authenticated jump box with session recording for vendor access
7. Patch management: Establish vendor-approved patch process with test environment validation
8. Logging and monitoring: Configure syslog forwarding to OT SIEM for all SCADA components
9. Backup and recovery: Implement verified backups for all PLC programs, HMI configurations, and historian data
10. Physical security: Secure control room, server rooms, and remote substation enclosures with access control

## Verification

- Network segmentation isolates IT/OT with firewall rules allowing only required protocols on specific ports
- HMI workstations run application whitelisting with no unauthorized software
- PLC/RTU default credentials are changed and programming access is restricted
- Remote access requires MFA with full session recording
- Patch management process is documented with test validation evidence
- All OT components forward logs to SIEM with defined retention
- Verified backups exist for all PLC programs and configurations
