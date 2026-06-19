---
name: iam-policy-audit
description: >-
  Identity and access management policy audit covering role-based access control, policy-as-code review,
  least privilege analysis, and cloud IAM entitlement review across AWS, Azure, GCP and on-prem AD.
domain: identity-access
subdomain: iam-policy-audit
tags: [iam, policy-audit, access-control, rbac, least-privilege, entitlement-review]
mitre_attack: [T1078, T1098, T1136, T1484, T1525]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, DE.CM-3, ID.AM-6]
d3fend: [D3-IAM, D3-PIM, D3-PAM, D3-CA]
nist_ai_rmf: [GOVERN-1.1, GOVERN-2.2, MEASURE-1.2, MAP-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during quarterly access reviews, after organizational restructuring, when implementing least-privilege initiatives, during compliance audits (SOC 2, SOX), and when deploying access certification campaigns.

## Prerequisites

- IAM platform access (AWS IAM, Azure AD, GCP IAM, AD, Okta)
- Identity governance tooling (SailPoint, Saviynt, Okta, or custom scripts)
- Python 3.10+ with cloud-specific SDKs for IAM analysis
- CSV/JSON exports of current permissions, role assignments, and access reviews
- Policy-as-code tools (Open Policy Agent, Cedar, AWS Access Analyzer)
- HR system integration for user status (active, terminated)

## Workflow

1. Inventory all identities: Collect users, groups, roles, service accounts, and application registrations across all platforms
2. Extract policy assignments: Map each identity to their granted permissions and roles
3. Identify unused permissions: Analyze IAM Access Advisor (AWS), AD effective access, or Azure AD sign-in logs for 90+ day inactivity
4. Review privileged roles: List all identities with admin, owner, or privileged role assignments (target: reduce by 50%)
5. Check for toxic combinations: Detect privilege pairs that violate segregation of duties (SoD) - e.g., user creation + billing admin
6. Analyze policy-as-code: Review OPA policies, Cedar policies, and CloudFormation/Terraform IAM configurations for overly permissive patterns
7. Validate RBAC assignments: Check user roles match job functions with HR data integration
8. Review cross-account trusts: Audit role trust policies and OAuth consent grants for excessive permissions
9. Conduct access certification: Send access review campaigns to managers for attestation of user entitlements
10. Generate compliance report: Document findings, remediation plans, and certification results

## Verification

- All privileged role assignments have documented business justification
- Unused permissions (90+ day inactive) are identified and removed
- SoD conflicts are documented with compensating controls or remediation plan
- Access certification completion rate >= 95% with all violations remediated
- Policy-as-code patterns do not contain wildcard permissions (*)
- Cross-account trust policies restrict to minimal required actions
