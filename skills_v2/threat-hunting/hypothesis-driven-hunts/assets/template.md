# Threat Hunt Report

## Hunt Information
- **Hunt ID**: {{hunt_id}}
- **Hypothesis**: {{hypothesis}}
- **Hunt Lead**: {{lead}}
- **Date**: {{date}}
- **Scope**: {{scope}}

## Hypothesis
**If** {{adversary}} **then we should observe** {{behavior}} **in** {{data_source}}

## Data Sources Used
| Source | Time Range | Volume |
|--------|------------|--------|
| {{source_1}} | {{time_1}} | {{volume_1}} |
| {{source_2}} | {{time_2}} | {{volume_2}} |

## Results Summary
- **Total Events Analyzed**: {{total_events}}
- **Confirmed Detections**: {{confirmed}}
- **False Positives**: {{fp}}
- **New IOCs**: {{new_iocs}}
- **Risk Score**: {{risk_score}}

## Findings
| Timestamp | Host | Indicator | Confidence | Notes |
|-----------|------|-----------|------------|-------|
| {{ts_1}} | {{host_1}} | {{indicator_1}} | {{confidence_1}} | {{notes_1}} |
| {{ts_2}} | {{host_2}} | {{indicator_2}} | {{confidence_2}} | {{notes_2}} |
| {{ts_3}} | {{host_3}} | {{indicator_3}} | {{confidence_3}} | {{notes_3}} |

## Detection Coverage Map
| ATT&CK Technique | Before Hunt | After Hunt | Improvement |
|------------------|-------------|------------|-------------|
| {{technique_1}} | {{before_1}} | {{after_1}} | {{improvement_1}} |
| {{technique_2}} | {{before_2}} | {{after_2}} | {{improvement_2}} |

## Recommendations
1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}
