# IOC Enrichment Report

## Batch Information
- **Batch ID**: {{batch_id}}
- **Enrichment Date**: {{date}}
- **IOC Count**: {{ioc_count}}
- **Sources Used**: {{sources}}

## Enrichment Summary
| Metric | Value |
|--------|-------|
| Total IOCs | {{total_iocs}} |
| Successfully Enriched | {{enriched}} |
| Cache Hits | {{cache_hits}} |
| Failed | {{failed}} |
| Enrichment Rate | {{enrichment_rate}}% |

## Threat Verdict Distribution
| Verdict | Count | Percentage |
|---------|-------|------------|
| Malicious | {{malicious_count}} | {{malicious_pct}}% |
| Suspicious | {{suspicious_count}} | {{suspicious_pct}}% |
| Unknown | {{unknown_count}} | {{unknown_pct}}% |
| Benign | {{benign_count}} | {{benign_pct}}% |

## Top Enriched IOCs
| IOC | Type | Score | Verdict | Top Source |
|-----|------|-------|---------|------------|
| {{ioc_1}} | {{ioc_1_type}} | {{ioc_1_score}} | {{ioc_1_verdict}} | {{ioc_1_source}} |
| {{ioc_2}} | {{ioc_2_type}} | {{ioc_2_score}} | {{ioc_2_verdict}} | {{ioc_2_source}} |
| {{ioc_3}} | {{ioc_3_type}} | {{ioc_3_score}} | {{ioc_3_verdict}} | {{ioc_3_source}} |

## Source Reliability
| Source | Successful | Failed | Avg Response Time |
|--------|------------|--------|-------------------|
| {{source_1}} | {{source_1_success}} | {{source_1_fail}} | {{source_1_time}}ms |
| {{source_2}} | {{source_2_success}} | {{source_2_fail}} | {{source_2_time}}ms |

## New Malicious Detections
- {{new_malicious_1}}
- {{new_malicious_2}}
- {{new_malicious_3}}
