# Standards Reference

## Splunk Correlation with Splunk Enterprise Security (ES)
| Correlation Type | Description | SPL Example |
|------------------|-------------|-------------|
| Single Event | Match single log event | `index=windows EventCode=4625 AccountName!=SYSTEM` |
| Multi-Event | Chain multiple log events | `index=windows | stats count by AccountName | where count > 10` |
| Aggregation | Count-based threshold | `index=fw action=block | stats count by src_ip | where count > 100` |
| Sequence | Events in specific order | `transaction maxpause=5m | search eventcode=4624 followedby eventcode=4672` |

## Elastic Security Rules
```kql
# Brute force detection with aggregation
sequence by user.name with maxspan=5m
  [authentication where event.action == "authentication_failure"] with runs=10
  [authentication where event.action == "authentication_success"]
```

## Microsoft Sentinel KQL
```kusto
// Multiple failed logons followed by success
let failed_threshold = 10;
SigninLogs
| where ResultType == "50057"
| summarize FailedCount = count() by UserPrincipalName, IPAddress
| where FailedCount > failed_threshold
| join kind=inner (
    SigninLogs
    | where ResultType == "0"
    | summarize SuccessTime = min(TimeGenerated) by UserPrincipalName, IPAddress
  ) on UserPrincipalName, IPAddress
| where SuccessTime > ago(1h)
```

## Detection Engineering Metrics
| Metric | Target | Measurement |
|--------|--------|-------------|
| True Positive Rate | > 95% | (TP / (TP + FN)) |
| False Positive Rate | < 5% | (FP / (FP + TP)) |
| Mean Time to Detect | < 15 min | Alert creation to analyst assignment |
| Precision | > 90% | TP / (TP + FP) |
| Recall | > 85% | TP / (TP + FN) |
| Coverage | > 80% | Techniques detected / total techniques |

## References
- Splunk Security Essentials: https://www.splunk.com/en_us/software/security-essentials.html
- Elastic Security: https://www.elastic.co/security
- Microsoft Sentinel Tiers: https://learn.microsoft.com/en-us/azure/sentinel/
- Sigma Rules: https://github.com/SigmaHQ/sigma
