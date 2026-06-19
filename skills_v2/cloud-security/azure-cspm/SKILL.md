---
name: azure-cspm
description: >-
  Continuous cloud security posture management for Microsoft Azure, implementing Microsoft Defender for Cloud recommendations
  and Azure Policy compliance checks across subscriptions, management groups, and resource groups.
domain: cloud-security
subdomain: azure-cspm
tags: [azure, cspm, cloud, defender, policy, compliance, security]
mitre_attack: [T1525, T1613, T1530]
nist_csf: [DE.CM-1, DE.CM-7, ID.AM-1, PR.AC-1, PR.AC-4, PR.DS-5, RS.MI-3]
d3fend: [D3-CA, D3-IAM, D3-AUDIT]
nist_ai_rmf: [MEASURE-1.1, GOVERN-2.3, MAP-3.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during Azure environment assessments, before deploying workloads to production, during defender for cloud recommendation evaluation, and for continuous compliance monitoring against Azure Security Benchmark and NIST SP 800-53 controls.

## Prerequisites

- Azure CLI (az) installed and authenticated with `az login`
- PowerShell 7+ with Az module (`Install-Module -Name Az -Force`)
- Azure Role: Security Reader or Contributor at management group scope
- Python 3.10+ with azure-identity and azure-mgmt-* packages
- Subscription ID and tenant ID accessible

## Workflow

1. Enumerate all subscriptions and management groups: `az account list --output table`
2. Enable Microsoft Defender for Cloud on all subscriptions: `az security auto-provisioning-setting update --name default --auto-provision On`
3. Deploy Azure Policy initiative for Azure Security Benchmark: Assign built-in initiative via portal or CLI
4. Run posture assessment: `az security task list` to review active recommendations
5. Review Identity & Access: Check Azure AD secure score, conditional access policies, and privileged role assignments
6. Audit Network Security: Review NSG rules, Azure Firewall policies, and VNet peering configurations
7. Validate Data Protection: Check SQL transparent data encryption, storage account firewall, and Key Vault soft-delete
8. Review Logging: Verify diagnostic settings on all resources and Log Analytics workspace retention
9. Check Microsoft Defender plans: Assess coverage for servers, SQL, storage, Key Vault, App Service, and containers
10. Generate compliance report: `python scripts/compliance_report.py --subscription-id <sub> --output pdf`

## Verification

- Confirm Azure Security Benchmark compliance score >= 85% across all subscriptions
- Verify Defender for Cloud is enabled on 100% of subscriptions
- Validate at least 90% of high-severity recommendations are remediated
- Confirm all storage accounts have firewall rules and HTTPS-only transfer enabled
- Check that Key Vault has soft-delete and purge protection enabled
- Verify Azure AD roles follow least-privilege with PIM for privileged roles
- Validate NSGs have no rules allowing 0.0.0.0/0 on management ports
