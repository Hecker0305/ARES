# SQL Injection Assessment Report

## Target Information
- **URL**: {{target_url}}
- **Parameter**: {{parameter}}
- **Method**: {{method}}
- **Assessor**: {{assessor}}
- **Date**: {{date}}

## Vulnerability Summary
| Detection Type | Confirmed | Payload |
|----------------|-----------|---------|
| Error-based | {{error_confirmed}} | {{error_payload}} |
| Boolean-blind | {{boolean_confirmed}} | {{boolean_payload}} |
| Time-blind | {{time_confirmed}} | {{time_payload}} |
| UNION-based | {{union_confirmed}} | {{union_payload}} |

## Database Fingerprint
- **DBMS**: {{dbms}}
- **Version**: {{version}}
- **User**: {{user}}
- **Privileges**: {{privileges}}

## Extracted Data
| Database | Table | Columns | Sample Data |
|----------|-------|---------|-------------|
| {{db_1}} | {{table_1}} | {{columns_1}} | {{data_1}} |
| {{db_2}} | {{table_2}} | {{columns_2}} | {{data_2}} |

## Impact Assessment
- **CVSS Score**: {{cvss_score}}
- **Risk**: {{risk}}
- **Data Exposure**: {{data_exposure}}
- **Authentication Bypass**: {{auth_bypass}}

## WAF/Filter Details
- WAF present: {{waf_present}}
- WAF bypass technique: {{waf_bypass}}
- Filter evasion: {{evasion}}

## Remediation
1. Use parameterized queries (prepared statements) for all database operations
2. Implement strict input validation and output encoding
3. Apply least-privilege database access controls
4. Deploy WAF rules to block SQLi patterns
5. Conduct regular code reviews for query construction
