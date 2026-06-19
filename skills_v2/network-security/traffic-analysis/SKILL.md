---
name: traffic-analysis
description: >-
  Network traffic analysis methodology using packet capture (PCAP) and NetFlow/IPFIX data for threat detection,
  protocol analysis, bandwidth monitoring, and forensic investigation of network-based attacks.
domain: network-security
subdomain: traffic-analysis
tags: [traffic-analysis, pcap, netflow, network-forensics, wireshark, zeek, packet-capture]
mitre_attack: [T1041, T1043, T1048, T1071, T1090, T1095, T1105, T1205, T1219, T1571, T1572]
nist_csf: [DE.AE-1, DE.AE-2, DE.CM-1, DE.CM-3, DE.CM-4, DE.CM-7, RS.AN-1]
d3fend: [D3-NDR, D3-NBA, D3-PCA, D3-SIEM]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-1.3, MONITOR-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during network incident investigation, when analyzing PCAP from breaches, during baseline traffic profiling, for threat hunting on network data, and when troubleshooting anomalous network behavior.

## Prerequisites

- Wireshark/TShark for PCAP analysis
- Zeek (Bro) for network metadata extraction
- Python 3.10+ with scapy, pyshark, pandas for programmatic analysis
- NetFlow/IPFIX collector (nfdump, SiLK, Elasticsearch)
- tcpdump for live packet capture
- Sufficient storage for PCAP retention (min 1TB recommended)
- Network taps or SPAN port access for packet capture

## Workflow

1. Acquire traffic data: Capture packets from the relevant network segment using tcpdump or access existing PCAP files
2. Extract metadata: Run Zeek on PCAPs to generate conn.log, dns.log, http.log, ssl.log, and files.log
3. Profile baseline: Analyze 7+ days of traffic to establish normal patterns (protocols, IPs, ports, bandwidth, timing)
4. Detect anomalies: Compare current traffic against baseline for deviations in volume, protocol mix, or destinations
5. Analyze DNS traffic: Look for domain generation algorithm patterns, long subdomains, and unusual query types
6. Review TLS/SSL: Examine certificates for self-signed certs, unusual SNI values, and TLS version negotiation
7. Detect C2 beacons: Identify periodic connections with consistent payload sizes and intervals
8. Examine file transfers: Extract and analyze files transferred over HTTP, SMTP, and SMB for malware
9. Correlate with IDS alerts: Cross-reference traffic patterns with IDS/IPS alerts for contextual investigation
10. Document findings: Create traffic analysis report with evidence, timestamps, and impact assessment

## Verification

- PCAPs are hash-verified (SHA-256) and timestamped for evidence integrity
- Zeek logs are complete and cover all protocol activity in the PCAP
- Baseline metrics represent at least 7 days of typical traffic patterns
- Anomaly detection identifies deviations beyond 3 standard deviations
- C2 beacon detection achieves < 1% false positive rate
- All extracted files are scanned by antivirus/malware analysis
