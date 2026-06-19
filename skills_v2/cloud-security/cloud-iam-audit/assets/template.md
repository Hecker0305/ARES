# Cloud IAM Audit Report

## Scope
- **Provider(s)**: {{providers}}
- **Account/Subscription/Project**: {{scope_id}}
- **Audit Date**: {{audit_date}}
- **Auditor**: {{auditor}}
- **Review Period**: {{review_period}}

## Executive Summary
- **Total Identities Reviewed**: {{total_identities}}
- **High Severity Findings**: {{high_severity}}
- **Medium Severity Findings**: {{medium_severity}}
- **Low Severity Findings**: {{low_severity}}
- **Compliance Score**: {{compliance_score}}%

## Privileged Access Review
| Identity | Role(s) | Scope | Last Used | MFA Enabled | Status |
|----------|---------|-------|-----------|-------------|--------|
| {{identity_1}} | {{role_1}} | {{scope_1}} | {{last_used_1}} | {{mfa_1}} | {{status_1}} |
| {{identity_2}} | {{role_2}} | {{scope_2}} | {{last_used_2}} | {{mfa_2}} | {{status_2}} |

## Unused Identities (90+ Days)
- {{unused_1}}
- {{unused_2}}
- {{unused_3}}

## Cross-Account Access
| Trust Relationship | Source | Target | Permission |
|--------------------|--------|--------|------------|
| {{trust_1_source}} -> {{trust_1_target}} | {{trust_1_permission}} | {{trust_1_condition}} |
| {{trust_2_source}} -> {{trust_2_target}} | {{trust_2_permission}} | {{trust_2_condition}} |

## Over-Permissive Policies
| Policy Name | Type | Permissions | Risk Level |
|-------------|------|-------------|------------|
| {{policy_1}} | {{policy_1_type}} | {{policy_1_perms}} | {{policy_1_risk}} |
| {{policy_2}} | {{policy_2_type}} | {{policy_2_perms}} | {{policy_2_risk}} |

## Service Account Review
- Active service accounts: {{sa_active}}
- Service accounts with keys >90 days: {{sa_old_keys}}
- Unused service accounts: {{sa_unused}}

## Remediation Plan
| Priority | Finding | Remediation | Owner | Timeline |
|----------|---------|-------------|-------|----------|
| P1 | {{finding_1}} | {{remediation_1}} | {{owner_1}} | {{timeline_1}} |
| P2 | {{finding_2}} | {{remediation_2}} | {{owner_2}} | {{timeline_2}} |
| P3 | {{finding_3}} | {{remediation_3}} | {{owner_3}} | {{timeline_3}} |
