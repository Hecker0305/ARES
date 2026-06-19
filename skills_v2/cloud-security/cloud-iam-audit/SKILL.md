---
name: cloud-iam-audit
description: >-
  Cloud-agnostic identity and access management audit methodology covering AWS IAM, Azure RBAC, and GCP IAM.
  Focuses on least-privilege analysis, unused permissions, role assignment creep, and cross-account access review.
domain: cloud-security
subdomain: cloud-iam-audit
tags: [iam, cloud, audit, identity, access-control, aws, azure, gcp]
mitre_attack: [T1098, T1136, T1525, T1550]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, DE.CM-3, ID.AM-6]
d3fend: [D3-IAM, D3-PIM, D3-PAM, D3-CA]
nist_ai_rmf: [GOVERN-1.1, GOVERN-2.3, MEASURE-1.2, MAP-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during cloud migration assessments, quarterly access reviews, after organizational restructuring, following security incidents involving credential compromise, or as part of compliance audits for SOC 2, ISO 27001, or FedRAMP.

## Prerequisites

- Multi-cloud CLI access (AWS CLI, Azure CLI, gcloud CLI)
- Cloud-specific SDK installations (boto3, azure-identity, google-cloud-resource-manager)
- SecurityAudit role on AWS, Security Reader on Azure, Security Reviewer on GCP
- Python 3.10+ with cloud-iam-audit library
- jq for JSON processing
- Network access to cloud provider APIs

## Workflow

1. Inventory all cloud providers: Collect account/subscription/project list with access levels
2. Identify privileged roles: List all users/roles with admin, owner, or contributor access
3. Detect unused identities: Identify IAM users, service accounts, or roles not used in 90+ days
4. Review cross-account access: Enumerate trust policies and role assumptions across AWS accounts, Azure AD B2B, GCP service account impersonation
5. Check for inline policies: Identify over-permissive inline policies (not manageable via IaC)
6. Validate MFA enforcement: Confirm MFA is required for all human users and privileged actions
7. Analyze service accounts: Review permissions, last used timestamps, and key rotation status
8. Check for standing privileges: Identify users with permanent high-privilege roles that should use just-in-time access
9. Generate IAM hygiene report with risk scoring
10. Produce remediation plan with policy-as-code templates

## Verification

- Confirm no human user has permanent admin-level access across any cloud provider
- Validate all inline policies are migrated to managed policies
- Check that unused IAM entities are disabled or removed
- Verify cross-account trust policies restrict source accounts and external IDs
- Confirm MFA is enforced for 100% of human user access
- Validate service account keys are rotated every 90 days or use workload identity federation
