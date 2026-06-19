---
name: ioc-enrichment
description: >-
  Automated enrichment of indicators of compromise using multiple intelligence sources.
  Adds context including geolocation, ASN, passive DNS, WHOIS, threat scores, and malware relationships.
domain: threat-intelligence
subdomain: ioc-enrichment
tags: [ioc, enrichment, threat-intelligence, context, osint, automation]
mitre_attack: [T1595, T1596]
nist_csf: [DE.AE-2, DE.AE-3, ID.RA-2, RS.AN-1]
d3fend: [D3-TIP, D3-IOC, D3-CTI, D3-ECR]
nist_ai_rmf: [MEASURE-2.1, MAP-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during incident response to enrich collected IOCs, before deploying indicators to detection infrastructure, for threat intelligence feed enhancement, when analyzing phishing campaigns, and for automated SOAR enrichment playbooks.

## Prerequisites

- API keys for enrichment sources (VirusTotal, AlienVault OTX, Shodan, AbuseIPDB, URLScan, IBM X-Force)
- Python 3.10+ with requests, urllib3, and rate-limiting libraries
- Redis or cache layer for rate limiting and deduplication
- SIEM or SOAR with enrichment API integration
- Threat intel platform for storing enriched IOCs
- Network connectivity to external API endpoints

## Workflow

1. Parse IOC batch: Extract indicators from input source (CSV, STIX, JSON, plain text) with type classification
2. Classify IOCs: Categorize by type (IPv4, IPv6, domain, URL, hash, email), normalize format (lowercase, trim)
3. Check local cache: Query Redis cache for previously enriched indicators to avoid redundant API calls
4. Enrich IP addresses: Query VirusTotal, AbuseIPDB, Shodan for geolocation, ASN, ISP, reputation score, historical resolution
5. Enrich domains/URLs: Query VirusTotal, URLScan, AlienVault for passive DNS, SSL certs, page content hash, phishing detections
6. Enrich file hashes: Query VirusTotal, Hybrid Analysis, MITRE ATT&CK for AV detections, malware family, sandbox reports
7. Calculate composite scores: Combine multiple source scores into a unified confidence/severity score
8. Tag and classify: Apply tags (malicious, suspicious, benign, untested) and threat categories (malware, phishing, C2, scanning)
9. Write enriched data: Store enriched IOCs in TIP or SIEM threat intel feed with enrichment timestamp and source attribution
10. Generate enrichment report: Produce summary with enrichment rates, source reliability, and new threat detections

## Verification

- All IOCs in the batch are enriched from at least one external source
- Enrichment cache hit rate is >= 50% for repeated IOC batches
- API rate limiting is functional and no source blocks occur
- Composite score calculation correctly weights source reliability and recency
- Enriched IOCs are searchable in TIP by confidence, type, and tag
- Enrichment latency is under 30 seconds per IOC for batch sizes under 100
- False positive indicators are tagged appropriately to avoid detection noise
