# Azure Security Posture Report

## Scope
- **Subscription ID**: {{subscription_id}}
- **Tenant ID**: {{tenant_id}}
- **Assessment Date**: {{date}}
- **Azure Security Benchmark Version**: {{benchmark_version}}

## Compliance Summary
| Control Domain | Compliant | Non-Compliant | Score |
|----------------|-----------|---------------|-------|
| Identity & Access | {{iam_compliant}} | {{iam_noncompliant}} | {{iam_score}}% |
| Networking | {{net_compliant}} | {{net_noncompliant}} | {{net_score}}% |
| Data Protection | {{data_compliant}} | {{data_noncompliant}} | {{data_score}}% |
| Logging & Monitoring | {{log_compliant}} | {{log_noncompliant}} | {{log_score}}% |

## Critical Recommendations

### {{rec_1_title}}
- **Severity**: High
- **Resource**: {{rec_1_resource}}
- **Current State**: {{rec_1_state}}
- **Remediation**: {{rec_1_remediation}}

## Defender for Cloud Coverage
- Virtual Machines: {{vm_coverage}}
- SQL Servers: {{sql_coverage}}
- Storage Accounts: {{storage_coverage}}
- Key Vault: {{kv_coverage}}
- App Service: {{app_coverage}}

## Network Security
- NSGs with 0.0.0.0/0 to SSH/RDP: {{open_nsgs}}
- Azure Firewall deployed: {{firewall_deployed}}
- VNet peering encryption: {{vnet_encryption}}

## Action Plan
| Priority | Issue | Remediation | Owner | Due Date |
|----------|-------|-------------|-------|----------|
| P1 | {{issue_1}} | {{remediation_1}} | {{owner_1}} | {{due_1}} |
| P2 | {{issue_2}} | {{remediation_2}} | {{owner_2}} | {{due_2}} |
| P3 | {{issue_3}} | {{remediation_3}} | {{owner_3}} | {{due_3}} |
