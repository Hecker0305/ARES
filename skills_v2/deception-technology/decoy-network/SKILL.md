---
name: decoy-network
description: >-
  Decoy network infrastructure deployment for advanced threat detection and attacker misdirection.
  Covers full decoy environment design including decoy AD, databases, file servers, applications,
  and OT systems with realistic network traffic emulation.
domain: deception-technology
subdomain: decoy-network
tags: [decoy-network, deception, decoy-environment, misdirection, attack-detection, active-defense]
mitre_attack: [T1043, T1046, T1082, T1090, T1105, T1133, T1190, T1557]
nist_csf: [DE.CM-1, DE.CM-4, DE.CM-7, RS.AN-1]
d3fend: [D3-DEC, D3-HN, D3-CD, D3-NDR]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during advanced deception program deployment, for creating realistic decoy environments that attract and detect sophisticated attackers, during red team detection capability testing, and for OT/IoT decoy network deployment.

## Prerequisites

- Virtualization infrastructure (VMware, Hyper-V, Proxmox) for decoy systems
- Network emulation tools (ns-3, GNS3, EVE-NG) for realistic network topology
- Decoy system templates (Windows Server, Linux, AD, SQL, Exchange, OT/ICS)
- Network monitoring (Zeek, Suricata) on decoy segments
- SIEM integration for decoy network alerts
- Python 3.10+ for traffic generation and decoy automation
- Isolated network segment with controlled egress (no production system access)

## Workflow

1. Design decoy network architecture: Create realistic network topology with VLANs, subnets, and routing reflecting production environment
2. Deploy decoy Active Directory: Set up decoy domain controller with realistic users, groups, GPOs, trusts, and service accounts
3. Deploy decoy servers: Install decoy application servers (SQL, Exchange, SharePoint, web servers, file servers) with realistic data
4. Deploy decoy workstations: Create decoy user workstations with realistic user activity simulation
5. Generate decoy traffic: Emulate realistic network traffic using Python scripts or traffic generators (browsing, email, file access, authentication)
6. Plant decoy credentials: Place realistic credential files, connection strings, and SSH keys in decoy systems
7. Enable decoy services: Run honeypot services that emulate critical infrastructure (RDP, SMB, SSH, WinRM, SQL, HTTP/HTTPS)
8. Monitor decoy segments: Deploy Zeek/Suricata on decoy network for full visibility, integrate alerts with SIEM
9. Implement egress controls: Decoy network has controlled egress to prevent pivot to production; alert on any attempted production access
10. Review and enhance: Analyze attacker interactions with decoy environment, enhance realism based on observed attacker expectations

## Verification

- Decoy network appears realistic to network scanning tools (nmap, Nessus, BloodHound)
- Decoy systems respond to recon tooling with realistic service banners and responses
- Decoy AD passes BloodHound enumeration with realistic attack paths
- Decoy traffic emulation mimics production traffic patterns (not constant or predictable)
- Any interaction with decoy network triggers immediate alert
- Decoy network cannot be used as pivot to production (isolation verified)
- Attacker dwell time in decoy environment is captured (interactions recorded)
- Decoy environment is updated regularly to maintain realism (patch levels, data freshness)
