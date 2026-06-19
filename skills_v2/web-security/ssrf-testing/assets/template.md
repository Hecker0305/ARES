# Server-Side Request Forgery Assessment Report

## Target Information
- **URL**: {{target_url}}
- **Parameter**: {{parameter}}
- **Method**: {{method}}
- **Assessor**: {{assessor}}
- **Date**: {{date}}

## SSRF Findings Summary
| Finding Type | Confirmed | Details |
|--------------|-----------|---------|
| External Callback | {{callback_confirmed}} | {{callback_details}} |
| Internal Host Access | {{internal_confirmed}} | {{internal_details}} |
| Cloud Metadata Access | {{metadata_confirmed}} | {{metadata_details}} |
| Protocol Smuggling | {{protocol_confirmed}} | {{protocol_details}} |

## Internal Hosts Discovered
| Host | Port | Service | Response |
|------|------|---------|----------|
| {{host_1}} | {{port_1}} | {{service_1}} | {{response_1}} |
| {{host_2}} | {{port_2}} | {{service_2}} | {{response_2}} |

## Cloud Metadata Access
| Provider | Endpoint | Data Retrieved |
|----------|----------|---------------|
| {{provider_1}} | {{endpoint_1}} | {{data_1}} |
| {{provider_2}} | {{endpoint_2}} | {{data_2}} |

## Impact Assessment
| Impact | Achieved | Details |
|--------|----------|---------|
| IAM Credential Access | {{iam_accessed}} | {{iam_details}} |
| Internal Service Access | {{internal_service}} | {{internal_service_details}} |
| Data Exfiltration | {{data_exfil}} | {{data_exfil_details}} |

## Bypass Techniques Used
- {{bypass_1}}
- {{bypass_2}}
- {{bypass_3}}

## Remediation
1. Implement allowlist-based URL validation (no blocklists)
2. Block access to RFC 1918 addresses and metadata endpoints
3. Use URL parser that rejects protocols other than http/https
4. Apply network segmentation with egress filtering
5. Use dedicated URL fetch service with strict timeouts
