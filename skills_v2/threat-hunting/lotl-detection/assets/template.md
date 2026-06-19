# Living-off-the-Land Detection Report

## Summary
- **Hunt Lead**: {{lead}}
- **Date Range**: {{date_range}}
- **Systems Scanned**: {{systems_scanned}}
- **Total Events Analyzed**: {{total_events}}
- **LOLBin Alerts**: {{alerts}}
- **Confirmed Malicious**: {{confirmed}}

## Most Common LOLBins Observed
| LOLBin | Usage Count | Suspicious | Admin Whitelisted |
|--------|-------------|------------|-------------------|
| {{lolbin_1}} | {{count_1}} | {{suspicious_1}} | {{whitelisted_1}} |
| {{lolbin_2}} | {{count_2}} | {{suspicious_2}} | {{whitelisted_2}} |
| {{lolbin_3}} | {{count_3}} | {{suspicious_3}} | {{whitelisted_3}} |

## Critical Alerts
| Time | Host | LOLBin | Command | Actor |
|------|------|--------|---------|-------|
| {{time_1}} | {{host_1}} | {{lolbin_alert_1}} | {{command_1}} | {{actor_1}} |
| {{time_2}} | {{host_2}} | {{lolbin_alert_2}} | {{command_2}} | {{actor_2}} |

## Baseline Activity
- Average daily PowerShell usage: {{avg_ps}}
- Average daily certutil usage: {{avg_certutil}}
- Top administrative users: {{admin_users}}
- Hourly distribution peak: {{hourly_peak}}

## MITRE ATT&CK Coverage Map
| Technique | Detection | Coverage |
|-----------|-----------|----------|
| T1059.001 - PowerShell | {{detect_ps}} | {{coverage_ps}}% |
| T1218.010 - Regsvr32 | {{detect_regsvr32}} | {{coverage_regsvr32}}% |
| T1218.005 - Mshta | {{detect_mshta}} | {{coverage_mshta}}% |
| T1047 - WMI | {{detect_wmi}} | {{coverage_wmi}}% |

## Recommendations
1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}
