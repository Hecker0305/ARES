# Cross-Site Scripting Assessment Report

## Target Information
- **URL**: {{target_url}}
- **Application**: {{application}}
- **Assessor**: {{assessor}}
- **Date**: {{date}}
- **Risk Level**: {{risk_level}}

## XSS Findings Summary
| Type | Confirmed | Count | Highest Severity |
|------|-----------|-------|------------------|
| Reflected | {{reflected_confirmed}} | {{reflected_count}} | {{reflected_severity}} |
| Stored | {{stored_confirmed}} | {{stored_count}} | {{stored_severity}} |
| DOM-based | {{dom_confirmed}} | {{dom_count}} | {{dom_severity}} |
| Blind | {{blind_confirmed}} | {{blind_count}} | {{blind_severity}} |

## Detailed Findings

### Finding XSS-01: Reflected XSS in {{param_1}}
- **Parameter**: {{param_1}}
- **Payload**: `{{payload_1}}`
- **URL**: {{url_1}}
- **Context**: {{context_1}}
- **CSP Status**: {{csp_1}}

### Finding XSS-02: {{finding_type}}
- **Parameter**: {{param_2}}
- **Payload**: `{{payload_2}}`
- **URL**: {{url_2}}
- **Context**: {{context_2}}
- **CSP Status**: {{csp_2}}

## CSP Analysis
- **CSP Enabled**: {{csp_enabled}}
- **Policy**: {{csp_policy}}
- **Bypass Found**: {{csp_bypass}}
- **Recommendation**: {{csp_recommendation}}

## Impact Assessment
- Session hijacking possible: {{session_hijack}}
- Credential theft possible: {{credential_theft}}
- Internal scanning possible: {{internal_scan}}
- Data exfiltration possible: {{data_exfil}}

## Remediation
1. Implement context-aware output encoding for all user input
2. Deploy strong CSP headers with no unsafe-inline
3. Use HTTPOnly and Secure cookie flags
4. Implement input validation on server side
5. Conduct code review for DOM sinks in JavaScript
6. Deploy XSS Auditor/WAF as additional protection layer
