# Decoy Network Incident Report

## Decoy Environment
- Network Segment: {{segment}}
- Systems Deployed: {{system_count}}
- Services Running: {{services}}
- Traffic Profile: {{traffic_profile}}

## Incident Details
- Detection Time: {{detection_time}}
- Attacker Entry Point: {{entry_point}}
- Compromised Decoy: {{compromised_system}}
- Attacker Actions: {{attacker_actions}}
- Tools Used: {{tools_detected}}

## Intelligence Gathered
| IOC Type | Value | Confidence |
|----------|-------|------------|
| IP | {{attacker_ip}} | High |
| Tool | {{tool_name}} | {{tool_confidence}} |
| TTP | {{ttp_id}} | {{ttp_confidence}} |

## Recommendations
- Update decoy realism: {{realism_updates}}
- Add decoys in {{new_segments}}
- Apply detection rules: {{detection_rules}}
