# UEBA Incident Investigation Report

## Alert Information
- **Alert ID**: {{alert_id}}
- **Risk Score**: {{risk_score}}
- **User**: {{user}}
- **Department**: {{department}}
- **Detected**: {{detected_time}}

## Behavioral Anomaly Details
| Feature | Baseline | Observed | Anomaly Score |
|---------|----------|----------|---------------|
| Login Hour | {{baseline_hour}} | {{observed_hour}} | {{score_hour}} |
| Location | {{baseline_location}} | {{observed_location}} | {{score_location}} |
| Device | {{baseline_device}} | {{observed_device}} | {{score_device}} |
| Volume | {{baseline_volume}} | {{observed_volume}} | {{score_volume}} |

## Activity Timeline
| Time | Event | Location | Device | Risk | Action |
|------|-------|----------|--------|------|--------|
| {{time_1}} | {{event_1}} | {{loc_1}} | {{dev_1}} | {{risk_1}} | {{action_1}} |
| {{time_2}} | {{event_2}} | {{loc_2}} | {{dev_2}} | {{risk_2}} | {{action_2}} |

## Peer Group Comparison
- User's peer group: {{peer_group}}
- Peer group size: {{peer_count}}
- User percentile for risk: {{risk_percentile}}
- Average peer risk score: {{peer_avg_risk}}

## Investigation Findings
- Confirmed legitimate: {{legitimate}}
- Confirmed malicious: {{malicious}}
- Inconclusive: {{inconclusive}}
- Action taken: {{action_taken}}

## Recommendations
1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}
