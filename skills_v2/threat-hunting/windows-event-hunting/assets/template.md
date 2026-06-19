# Windows Event Log Hunting Report

## Investigation Summary
- **Case ID**: {{case_id}}
- **Target Host**: {{target_host}}
- **Time Range**: {{start_time}} to {{end_time}}
- **Analyst**: {{analyst}}
- **Total Events Collected**: {{total_events}}

## Event Distribution by ID
| Event ID | Description | Count | Suspicious |
|----------|-------------|-------|------------|
| {{eid_1}} | {{eid_1_desc}} | {{eid_1_count}} | {{eid_1_suspicious}} |
| {{eid_2}} | {{eid_2_desc}} | {{eid_2_count}} | {{eid_2_suspicious}} |
| {{eid_3}} | {{eid_3_desc}} | {{eid_3_count}} | {{eid_3_suspicious}} |

## Logon Anomalies
| Timestamp | User | Source IP | Logon Type | Account Used | Status |
|-----------|------|-----------|------------|--------------|--------|
| {{ts_1}} | {{user_1}} | {{src_ip_1}} | {{logon_type_1}} | {{account_1}} | {{status_1}} |
| {{ts_2}} | {{user_2}} | {{src_ip_2}} | {{logon_type_2}} | {{account_2}} | {{status_2}} |

## Process Execution Timeline
| Time | Parent Process | Process | User | Command Line |
|------|---------------|---------|------|-------------|
| {{ptime_1}} | {{parent_1}} | {{process_1}} | {{puser_1}} | {{cmdline_1}} |
| {{ptime_2}} | {{parent_2}} | {{process_2}} | {{puser_2}} | {{cmdline_2}} |

## Service & Scheduled Task Changes
- New services installed: {{new_services}}
- New scheduled tasks: {{new_tasks}}
- Service modifications: {{service_changes}}

## Active Directory Changes
- New users: {{new_users}}
- Group modifications: {{group_changes}}
- Privilege escalations: {{priv_escalations}}
- Account lockouts: {{lockouts}}

## Critical Findings
1. {{finding_1}}
2. {{finding_2}}
3. {{finding_3}}

## Investigation Actions Taken
{{investigation_actions}}

## Recommendations
1. {{recommendation_1}}
2. {{recommendation_2}}
