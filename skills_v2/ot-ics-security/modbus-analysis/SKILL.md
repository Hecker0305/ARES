---
name: modbus-analysis
description: >-
  Modbus/TCP and Modbus/RTU protocol security analysis for OT/ICS environments. Covers function code auditing,
  unit identifier scanning, Modbus vulnerability detection, and anomaly-based threat detection.
domain: ot-ics-security
subdomain: modbus-analysis
tags: [modbus, ot-security, ics, scada, protocol-analysis, function-codes, industrial]
mitre_attack: [T0811, T0816, T0835, T0836, T0839, T0842, T0855, T0865, T0883]
nist_csf: [PR.AC-4, PR.AC-5, PR.PT-1, PR.PT-2, DE.CM-1, DE.CM-4, DE.CM-7]
d3fend: [D3-MOD, D3-NIDS, D3-PCA, D3-FW]
nist_ai_rmf: [GOVERN-2.1, MEASURE-1.2, MAP-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during OT network security assessments, Modbus network segmentation review, ICS incident response involving Modbus devices, vulnerability scanning of Modbus-enabled PLCs and RTUs, and when monitoring Modbus traffic for anomalies.

## Prerequisites

- Network access to OT network segment (SPAN port or network tap)
- Wireshark with Modbus dissector for packet analysis
- Modbus scanning tools (nmap with modbus-discover, Modscan, ModbusPal)
- Python 3.10+ with pymodbus library for custom analysis
- PLC/RTU hardware or simulation for testing (OpenPLC, ModbusPal)
- Understanding of Modbus function codes and register addressing
- OT network diagram with device IPs and Modbus roles

## Workflow

1. Discover Modbus devices: Scan for Modbus/TCP devices on port 502 using nmap: `nmap -p 502 --script modbus-discover <subnet>`
2. Enumerate function codes: Probe each device for supported function codes (1, 2, 3, 4, 5, 6, 15, 16, 22, 23)
3. Identify unprotected operations: Check if write functions (FC5, FC6, FC15, FC16) are accessible without authentication
4. Capture traffic baseline: Record 24+ hours of normal Modbus traffic to establish register access patterns
5. Analyze function code distribution: Identify unusual function code usage that deviates from operational requirements
6. Monitor for unauthorized writes: Alert on Modbus write operations (FC5, FC6, FC15, FC16) from unexpected source IPs
7. Detect register scanning: Identify sequential register reads across large address ranges (possible reconnaissance)
8. Check unit identifier access: Test access to multiple unit identifiers (slave IDs) on each Modbus gateway
9. Implement segmentation: Verify Modbus traffic is restricted to required device pairs with firewall rules
10. Create detection rules: Develop IDS rules for Modbus anomalies (force listen only, restart communication, diagnostic registers)

## Verification

- All Modbus devices on the network are discovered and documented
- Unnecessary function codes (especially write functions) are blocked at the firewall
- Modbus write operations are restricted to known management stations only
- Register scanning detection alerts on sequential access patterns
- Unit identifier access is restricted to authorized devices only
- Modbus/TCP traffic is on isolated OT network segment with no direct IT access
- Anomalous Modbus function code usage triggers security alerts
