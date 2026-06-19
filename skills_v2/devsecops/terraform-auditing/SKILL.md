---
name: terraform-auditing
description: >-
  Terraform infrastructure-as-code security auditing covering policy-as-code enforcement (OPA/Sentinel),
  state file security, secret detection in code, cloud resource misconfiguration scanning, and drift detection.
domain: devsecops
subdomain: terraform-auditing
tags: [terraform, iac, policy-as-code, opa, sentinel, cloud-misconfiguration, devsecops]
mitre_attack: [T1525]
nist_csf: [PR.AC-4, PR.DS-5, PR.IP-3, de.cm-1, de.cm-4, de.cm-7]
d3fend: [D3-IAC, D3-CSPM, D3-PVM]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1, MAP-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during Terraform code review and auditing, when integrating IaC security into CI/CD, for cloud resource misconfiguration detection, and when enforcing compliance policies through code.

## Prerequisites

- Terraform configuration files (HCL format) for target infrastructure
- IaC scanning tools (Checkov, tfsec, Terrascan, Snyk IaC)
- Policy-as-code tools (OPA/Rego, Sentinel, Azure Policy)
- Terraform state file access (read-only)
- Python 3.10+ for policy automation and reporting
- Cloud provider credentials for drift detection

## Workflow

1. Scan Terraform code: Run Checkov/tfsec against all Terraform directories to identify cloud misconfigurations
2. Check secrets in code: Scan .tf files and .tfvars for hard-coded secrets, passwords, API keys, and private keys
3. Review IAM permissions: Audit terraform-managed IAM resources for over-privileged roles, wildcard permissions, and public access
4. Validate network security: Check security groups for unrestricted ingress, ensure encryption in transit for key services
5. Verify encryption at rest: Ensure all storage resources (S3, EBS, RDS, Cloud SQL) have encryption at rest enabled
6. Audit logging configuration: Check CloudTrail, VPC Flow Logs, and audit log configurations
7. Enforce policies with OPA: Write Rego policies to enforce tagging, region restrictions, resource size limits, and security controls
8. Review state file security: Ensure state files are stored in encrypted backends (S3 with DynamoDB lock, Terraform Cloud) with access controls
9. Check module versions: Validate Terraform module versions from registry, ensure no deprecated providers
10. Detect drift: Compare Terraform state against actual cloud resources, report unauthorized changes

## Verification

- IaC scanning covers all Terraform files with pass/fail results for each policy
- No secrets are found in Terraform code or state files
- All IAM policies follow least privilege (no `*` actions, no `*` resources on sensitive services)
- Encryption is enforced (at rest and in transit) for all supported resources
- Logging is enabled for all regions and services
- OPA policies are enforced in CI/CD pipeline (build fails on policy violation)
- State file backend is encrypted and backed up
- Drift detection report shows no unauthorized infrastructure changes
