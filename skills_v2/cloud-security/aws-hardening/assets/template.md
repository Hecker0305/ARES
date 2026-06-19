# AWS Hardening Assessment Report

## Environment
- **Account ID**: {{account_id}}
- **Region(s)**: {{regions}}
- **Assessment Date**: {{date}}
- **Assessor**: {{assessor}}

## Summary
| Category | Pass | Fail | Not Applicable |
|----------|------|------|----------------|
| IAM | {{iam_pass}} | {{iam_fail}} | {{iam_na}} |
| S3 | {{s3_pass}} | {{s3_fail}} | {{s3_na}} |
| CloudTrail | {{ct_pass}} | {{ct_fail}} | {{ct_na}} |
| VPC | {{vpc_pass}} | {{vpc_fail}} | {{vpc_na}} |
| KMS | {{kms_pass}} | {{kms_fail}} | {{kms_na}} |
| **Total** | {{total_pass}} | {{total_fail}} | {{total_na}} |

## Critical Findings

### {{finding_1_title}}
- **Resource**: {{finding_1_resource}}
- **Severity**: Critical
- **Description**: {{finding_1_description}}
- **Remediation**: {{finding_1_remediation}}
- **CIS Reference**: {{finding_1_cis_ref}}

### {{finding_2_title}}
- **Resource**: {{finding_2_resource}}
- **Severity**: High
- **Description**: {{finding_2_description}}
- **Remediation**: {{finding_2_remediation}}
- **CIS Reference**: {{finding_2_cis_ref}}

## IAM Review
- Root account MFA enabled: {{root_mfa}}
- IAM password policy compliant: {{password_policy}}
- Access keys older than 90 days: {{old_keys}}
- Unused IAM roles: {{unused_roles}}

## S3 Configuration
- Block Public Access enabled at account level: {{account_pab}}
- Default encryption enabled: {{default_encryption}}
- Versioning enabled: {{versioning}}

## CloudTrail Configuration
- Multi-region trail enabled: {{multi_region_trail}}
- Log file validation: {{log_validation}}
- SSE-KMS encryption: {{trail_encryption}}

## Action Items
1. {{action_item_1}}
2. {{action_item_2}}
3. {{action_item_3}}
4. {{action_item_4}}

## Remediation Timeline
| Priority | Finding | Due Date | Owner |
|----------|---------|----------|-------|
| P1 | {{p1_finding}} | {{p1_date}} | {{p1_owner}} |
| P2 | {{p2_finding}} | {{p2_date}} | {{p2_owner}} |
| P3 | {{p3_finding}} | {{p3_date}} | {{p3_owner}} |
