# Standards Reference

## SOAR Playbook Structure
```yaml
playbook:
  name: "Phishing Email Triage"
  trigger:
    type: "email_submission"
    source: "phishing_reporting@company.com"
  steps:
    - action: "extract_indicators"
      params:
        extract_urls: true
        extract_attachments: true
    - action: "enrich_iocs"
      params:
        sources: ["virustotal", "abuseipdb", "urlscan"]
    - action: "decision"
      condition: "{{steps.enrich_iocs.malicious_count > 0}}"
      branch:
        true: "contain_indicators"
        false: "close_as_benign"
```

## Common SOAR Workflows
| Workflow | Enrichment | Containment | Notification |
|----------|------------|-------------|--------------|
| Phishing | URL scan, hash lookup, header analysis | Block URL in proxy, delete email | User notification |
| Brute Force | Source IP reputation, geo-location | Block IP in firewall | Account owner |
| Malware Alert | Hash lookup, process correlation | Isolate endpoint | Incident response |
| DLP Event | Data classification, user context | Block transmission | Privacy officer |
| Compromised User | Login analysis, device check | Disable account, reset sessions | User manager |

## Containment Actions (by Severity)
| Severity | Automated | Manual Approval | Notification |
|----------|-----------|-----------------|--------------|
| Critical | Block IP (firewall), isolate endpoint (EDR) | Disable account, contain with DLP | CISO, IR team |
| High | Block URL (proxy), kill process (EDR) | Disable service account | SOC Manager |
| Medium | Add to watchlist, enrich further | Create investigation case | Analyst |
| Low | Tag for review | N/A | None |

## References
- Splunk SOAR: https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html
- Palo Alto XSOAR: https://www.paloaltonetworks.com/cortex/xsoar
- Swimlane: https://swimlane.com
- OASIS CACAO: https://www.oasis-open.org/committees/cacao/
