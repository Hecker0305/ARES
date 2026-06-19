---
name: aws-hardening
description: >-
  Systematic hardening of AWS infrastructure following the CIS AWS Foundations Benchmark and AWS Well-Architected Framework security pillar.
  Covers IAM, S3, VPC, CloudTrail, and encryption configuration reviews with automated remediation playbooks.
domain: cloud-security
subdomain: aws-hardening
tags: [aws, hardening, cloud, cis-benchmarks, security, iam, s3, vpc]
mitre_attack: [T1525, T1530, T1613]
nist_csf: [DE.CM-1, DE.CM-7, ID.AM-1, PR.AC-1, PR.AC-3, PR.DS-1, PR.DS-5, PR.PT-1, PR.PT-3]
mitre_atlas: [AML.T0020]
d3fend: [D3-HN, D3-CA, D3-IAM, D3-ENC]
nist_ai_rmf: [MEASURE-2.1, MEASURE-3.2, GOVERN-4.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when conducting AWS security audits, after provisioning new AWS accounts, or as part of a cloud security posture management (CSPM) program. Use during initial cloud environment assessment, before production deployments, and during periodic compliance reviews against CIS AWS Foundations Benchmark v2.0.

## Prerequisites

- AWS CLI v2 configured with ReadOnlyAccess or SecurityAudit role
- AWS Account ID and organization access
- Python 3.10+ with boto3 and policy_sentry installed
- jq and yq for JSON/YAML processing
- Access to AWS Organizations if reviewing multi-account setups
- IAM permissions: cloudtrail:DescribeTrails, s3:GetBucket*, ec2:Describe*, iam:Get*, iam:List*, kms:Describe*, kms:List*

## Workflow

1. Run CIS benchmark scan using custom script: `python scripts/cis_scanner.py --profile <profile> --region <region>`
2. Review IAM password policy: Verify `MinimumPasswordLength >= 14`, require uppercase, lowercase, numbers, and symbols
3. Audit S3 bucket configurations: Check for public access blocks, bucket policies, encryption (SSE-S3 or SSE-KMS), and versioning
4. Validate CloudTrail: Ensure trails are enabled in all regions, log file validation enabled, and logs are delivered to S3 with SSE-KMS
5. Check VPC Flow Logs: Verify enabled for all VPCs with retention >= 365 days
6. Review KMS key rotation: Confirm automatic rotation (annual) on all customer-managed keys
7. Audit IAM roles and policies: Identify unused roles, over-permissive policies, and inline policies using Access Analyzer
8. Verify AWS Config rules: Check that required config rules are enabled (e.g., s3-bucket-public-read-prohibited, restricted-ssh, encrypted-volumes)
9. Run Security Hub: Review findings across CIS, PCI DSS, and AWS Foundational Security Best Practices
10. Generate hardening report: `python scripts/hardening_report.py --output html`

## Verification

- Confirm all CIS level-1 recommendations are implemented with >= 90% compliance
- Verify S3 Block Public Access is enabled at account level
- Validate that no IAM user has access keys older than 90 days
- Check that root account MFA is enabled and activity is monitored
- Confirm CloudTrail logs are delivered to a centralized S3 bucket in under 15 minutes
- Verify all EBS volumes and RDS instances are encrypted at rest
- Validate VPC default security groups deny all inbound traffic
