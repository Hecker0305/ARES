# MISP Threat Intel Event Report

## Event Information
- **Event ID**: {{event_id}}
- **Info**: {{event_info}}
- **Created**: {{created}}
- **Last Modified**: {{modified}}
- **Published**: {{published}}
- **Threat Level**: {{threat_level}}
- **Distribution**: {{distribution}}
- **Analysis**: {{analysis}}

## Attribute Summary
| Category | Count | Notable Values |
|----------|-------|----------------|
| Network activity | {{network_count}} | {{network_values}} |
| Payload delivery | {{payload_count}} | {{payload_values}} |
| Artifacts dropped | {{artifact_count}} | {{artifact_values}} |
| Antivirus detection | {{av_count}} | {{av_values}} |
| Persistence mechanism | {{persist_count}} | {{persist_values}} |

## Tags Applied
- {{tag_1}}
- {{tag_2}}
- {{tag_3}}

## Correlation Results
- Linked events: {{linked_events}}
- Correlation rate: {{correlation_rate}}%
- Shared attributes across orgs: {{shared_attributes}}

## Indicators
| Value | Type | Category | TLP | Confidence |
|-------|------|----------|-----|------------|
| {{ioc_1}} | {{ioc_1_type}} | {{ioc_1_cat}} | {{ioc_1_tlp}} | {{ioc_1_conf}} |
| {{ioc_2}} | {{ioc_2_type}} | {{ioc_2_cat}} | {{ioc_2_tlp}} | {{ioc_2_conf}} |
| {{ioc_3}} | {{ioc_3_type}} | {{ioc_3_cat}} | {{ioc_3_tlp}} | {{ioc_3_conf}} |

## Feed Distribution
- TAXII feed: {{taxii_feed}}
- CSV export: {{csv_export}}
- STIX export: {{stix_export}}
- ZMQ notification: {{zmq_status}}

## Related Events
| Event ID | Info | Org | Date |
|----------|------|-----|------|
| {{rel_event_1}} | {{rel_event_1_info}} | {{rel_event_1_org}} | {{rel_event_1_date}} |
| {{rel_event_2}} | {{rel_event_2_info}} | {{rel_event_2_org}} | {{rel_event_2_date}} |
