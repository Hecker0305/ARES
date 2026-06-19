# Network Traffic Analysis Report

## Case Information
- **Case ID**: {{case_id}}
- **PCAP Source**: {{pcap_source}}
- **Time Range**: {{start_time}} to {{end_time}}
- **Analyst**: {{analyst}}
- **Total Packets**: {{total_packets}}

## Summary Statistics
| Metric | Value |
|--------|-------|
| Total Flows | {{total_flows}} |
| Unique IPs (Internal) | {{internal_ips}} |
| Unique IPs (External) | {{external_ips}} |
| Protocols (Top 3) | {{top_protocols}} |
| Total Data Transferred | {{total_data}} |
| Malware Detected | {{malware_detected}} |

## Beaconing Analysis
| Source | Destination | Port | Connections | CV Score | Assessment |
|--------|-------------|------|-------------|----------|------------|
| {{beacon_src_1}} | {{beacon_dst_1}} | {{beacon_port_1}} | {{beacon_count_1}} | {{beacon_cv_1}} | {{beacon_assessment_1}} |
| {{beacon_src_2}} | {{beacon_dst_2}} | {{beacon_port_2}} | {{beacon_count_2}} | {{beacon_cv_2}} | {{beacon_assessment_2}} |

## DNS Anomalies
| Timestamp | Query | Type | Suspicious |
|-----------|-------|------|------------|
| {{dns_ts_1}} | {{dns_query_1}} | {{dns_type_1}} | {{dns_suspicious_1}} |
| {{dns_ts_2}} | {{dns_query_2}} | {{dns_type_2}} | {{dns_suspicious_2}} |

## TLS/SSL Certificate Anomalies
| Server Name | Issuer | Valid | Self-Signed |
|-------------|--------|-------|-------------|
| {{ssl_sni_1}} | {{ssl_issuer_1}} | {{ssl_valid_1}} | {{ssl_self_1}} |
| {{ssl_sni_2}} | {{ssl_issuer_2}} | {{ssl_valid_2}} | {{ssl_self_2}} |

## File Transfers
| Filename | MIME Type | Size | Hash | Verdict |
|----------|-----------|------|------|---------|
| {{file_1}} | {{mime_1}} | {{size_1}} | {{hash_1}} | {{verdict_1}} |
| {{file_2}} | {{mime_2}} | {{size_2}} | {{hash_2}} | {{verdict_2}} |

## Connections to Known Bad IPs
{{bad_connections}}

## Recommendations
1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}
