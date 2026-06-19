---
name: stix-taxii-ingestion
description: >-
  Automated ingestion of structured threat intelligence using STIX 2.1 and TAXII 2.1 protocol.
  Covers TAXII server discovery, collection management, indicator and relationship processing, and integration with SIEM.
domain: threat-intelligence
subdomain: stix-taxii-ingestion
tags: [stix, taxii, threat-intelligence, cti, indicators, ioc, automation]
mitre_attack: [T1595, T1596, T1597, T1598]
nist_csf: [DE.AE-1, DE.AE-2, DE.AE-3, DE.CM-1, DE.CM-4, ID.RA-2, ID.RA-3]
d3fend: [D3-TIP, D3-SIEM, D3-IOC, D3-FW]
nist_ai_rmf: [GOVERN-1.3, MAP-2.1, MEASURE-2.2, MANAGE-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when setting up a new threat intelligence platform or TAXII feed, needing to automate IOC ingestion from external sources (botvrij, AlienVault OTX, MISP, Anomali), during threat intelligence lifecycle management, or when integrating CTI with detection infrastructure.

## Prerequisites

- TAXII 2.1 server URL(s) and API credentials (API key or username/password)
- Python 3.10+ with stix2, taxii2-client, and stix-shifter libraries
- SIEM or detection platform API for indicator deployment (Splunk, Elastic, Sentinel)
- PostgreSQL or similar storage for indicator persistence
- Redis or cache layer for deduplication
- Network access to TAXII endpoints (usually TCP 443)
- TLS certificate validation capability

## Workflow

1. Discover TAXII endpoint: Query `GET /taxii2/` to retrieve API root information and supported versions
2. List available collections: Query `GET /collections/` to enumerate data collections with names and descriptions
3. Authenticate and get token: Exchange credentials for bearer token, store with proper expiration handling
4. Select collections: Based on relevance, select collections (e.g., C2 indicators, malware, phishing, ransomware)
5. Define poll parameters: Set time range (last X hours/days), indicator types (IP, domain, hash, URL), and confidence threshold
6. Poll for new indicators: `GET /collections/{id}/objects/` with added_after parameter for incremental ingestion
7. Parse STIX objects: Extract Indicators, Observable, Relationships, and Attack Patterns from STIX bundle
8. Deduplicate indicators: Check Redis cache for existing indicator hashes before storing
9. Enrich indicators: Add context from enrichment sources (geolocation, ASN, WHOIS, passive DNS)
10. Deploy to detection: Push indicators to SIEM threat intel feeds, firewall/DNS blocklists, and endpoint protection

## Verification

- TAXII connection is established with successful authentication
- All selected collections are polled at configured intervals (typically 15-60 minutes)
- Indicator processing rate is documented (IOCs/minute)
- Deduplication rate is >= 95% for repeated polling cycles
- Indicator enrichment success rate is >= 90% for IP-based indicators
- SIEM integration delivers indicators within 5 minutes of ingestion
- Error handling for API failures and rate limiting is functional
