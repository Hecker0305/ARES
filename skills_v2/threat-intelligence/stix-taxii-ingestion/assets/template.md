# TAXII Ingestion Report

## Feed Information
- **Server**: {{server_url}}
- **Collection**: {{collection_name}} ({{collection_id}})
- **Poll Time**: {{poll_time}}
- **Poll Duration**: {{duration}}s

## Ingestion Statistics
| Metric | Value |
|--------|-------|
| Objects Retrieved | {{objects_retrieved}} |
| New Indicators | {{new_indicators}} |
| Duplicates (Skipped) | {{duplicates}} |
| Enrichment Success | {{enrichment_success}}% |
| SIEM Push Success | {{siem_success}}% |

## Indicator Breakdown by Type
| Type | Count | New | Expired |
|------|-------|-----|---------|
| IP Address | {{ip_count}} | {{ip_new}} | {{ip_expired}} |
| Domain | {{domain_count}} | {{domain_new}} | {{domain_expired}} |
| URL | {{url_count}} | {{url_new}} | {{url_expired}} |
| MD5 | {{md5_count}} | {{md5_new}} | {{md5_expired}} |
| SHA256 | {{sha256_count}} | {{sha256_new}} | {{sha256_expired}} |

## Top Confidence Scores
| IOC Value | Type | Confidence | Label |
|-----------|------|------------|-------|
| {{ioc_1_value}} | {{ioc_1_type}} | {{ioc_1_conf}} | {{ioc_1_label}} |
| {{ioc_2_value}} | {{ioc_2_type}} | {{ioc_2_conf}} | {{ioc_2_label}} |

## Deployment Status
- Firewall blocklist updated: {{firewall_updated}}
- DNS sinkhole updated: {{dns_updated}}
- SIEM threat intel feed updated: {{siem_updated}}
- EDR IOC list updated: {{edr_updated}}

## Errors/Warnings
{{errors}}

## Next Scheduled Poll
{{next_poll}}
