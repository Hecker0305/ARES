# IDS/IPS Analysis Report

## Sensor Information
- **Sensor Name**: {{sensor_name}}
- **Sensor Type**: {{sensor_type}} (Snort/Suricata/Zeek)
- **Network Segment**: {{network_segment}}
- **Analysis Period**: {{start_date}} to {{end_date}}

## Performance Metrics
| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Avg Alerts/Second | {{avg_aps}} | < 1000 | {{aps_status}} |
| CPU Utilization | {{cpu_usage}}% | < 60% | {{cpu_status}} |
| Memory Usage | {{mem_usage}}% | < 80% | {{mem_status}} |
| Packet Loss | {{packet_loss}}% | < 0.01% | {{pl_status}} |
| False Positive Rate | {{fp_rate}}% | < 5% | {{fp_status}} |

## Top Alert Signatures
| SID | Signature | Count | Severity | FP Rate |
|-----|-----------|-------|----------|---------|
| {{sid_1}} | {{sig_1}} | {{count_1}} | {{sev_1}} | {{fp_1}}% |
| {{sid_2}} | {{sig_2}} | {{count_2}} | {{sev_2}} | {{fp_2}}% |
| {{sid_3}} | {{sig_3}} | {{count_3}} | {{sev_3}} | {{fp_3}}% |

## Top Source IPs
| IP Address | Alert Count | Top Signature |
|------------|-------------|---------------|
| {{src_ip_1}} | {{src_count_1}} | {{src_sig_1}} |
| {{src_ip_2}} | {{src_count_2}} | {{src_sig_2}} |

## Rule Changes This Period
| Date | SID | Action | Reason |
|------|-----|--------|--------|
| {{change_date_1}} | {{change_sid_1}} | {{change_action_1}} | {{change_reason_1}} |
| {{change_date_2}} | {{change_sid_2}} | {{change_action_2}} | {{change_reason_2}} |

## Custom Rules Deployed
| SID | Name | Created | Source |
|-----|------|---------|--------|
| {{custom_sid_1}} | {{custom_name_1}} | {{custom_date_1}} | {{custom_source_1}} |

## Recommendations
1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}
