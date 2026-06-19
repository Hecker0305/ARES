---
name: vlan-segmentation
description: >-
  VLAN segmentation assessment and hardening for network security, covering VLAN hopping prevention,
  trunk configuration review, spanning tree hardening, PVLAN isolation, and 802.1X enforcement.
domain: network-security
subdomain: vlan-segmentation
tags: [vlan, segmentation, network-security, switching, trunking, access-control, dot1q]
mitre_attack: [T1048, T1090, T1557, T1574]
nist_csf: [PR.AC-4, PR.AC-5, PR.PT-3, PR.PT-4, DE.CM-1]
d3fend: [D3-VLAN, D3-NACL, D3-SG, D3-SDN]
nist_ai_rmf: [GOVERN-1.2, MAP-2.1, MEASURE-3.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during network segmentation reviews, after network infrastructure changes, when implementing PCI DSS network segmentation (requirement 1), during zero trust network architecture design, and when auditing switch configurations for VLAN security.

## Prerequisites

- SSH/Telnet access to managed switches (Cisco, Juniper, Arista, HP, Dell)
- Network diagram with VLAN assignments and trunk ports
- Python 3.10+ with netmiko, napalm, or scrapli for switch config extraction
- Understanding of 802.1Q, DTP, VTP, STP protocols
- SNMP read access for VLAN discovery if CLI unavailable

## Workflow

1. Discover VLAN configuration: Collect VLAN databases, trunk ports, access ports, and allowed VLAN lists from all switches
2. Audit trunk ports: Verify trunks are configured with specific allowed VLANs (not `switchport trunk allowed vlan all` or default)
3. Check DTP state: Ensure Dynamic Trunking Protocol is disabled on all ports (`switchport nonegotiate`) to prevent VLAN hopping
4. Review native VLAN: Change native VLAN from default VLAN 1 to unused VLAN ID on all trunk ports
5. Verify PVLAN configuration: Check private VLANs for properly isolating community and isolated ports
6. Audit VLAN 1 usage: Identify and migrate all ports from default VLAN 1 to purpose-specific VLANs
7. Review VTP settings: Set VTP to transparent mode or disable entirely to prevent VLAN propagation attacks
8. Check STP security: Enable BPDU guard on all access ports, root guard on designated root ports, and loop guard
9. Validate 802.1X: Check port-based authentication is configured on all edge ports for device authentication
10. Test VLAN hopping: Attempt double-tagging and switch spoofing attacks to validate mitigation controls

## Verification

- No trunk ports allow all VLANs; each trunk has explicit allow list
- DTP is disabled on all access ports; trunk ports use `switchport nonegotiate`
- Native VLAN is not VLAN 1 on any trunk port
- BPDU guard is enabled on all access ports
- VLAN 1 is not in use for any data traffic
- VTP is in transparent mode or disabled
- Double-tagging attack is mitigated by native VLAN change
- All ports are assigned to a specific VLAN; no ports in default VLAN
