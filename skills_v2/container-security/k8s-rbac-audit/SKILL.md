---
name: k8s-rbac-audit
description: >-
  Kubernetes Role-Based Access Control security audit covering cluster roles, role bindings, service accounts,
  RBAC abuse detection, privilege escalation paths, and least privilege analysis.
domain: container-security
subdomain: k8s-rbac-audit
tags: [kubernetes, rbac, service-account, cluster-role, security-audit, container]
mitre_attack: [T1078, T1098, T1525, T1550, T1613]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, DE.CM-1, DE.CM-3, DE.CM-7]
d3fend: [D3-IAM, D3-PIM, D3-CA, D3-ZTA]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during Kubernetes cluster security assessments, service account permission reviews, RBAC policy audits, compliance assessments (CIS EKS/GKE/AKS), and when implementing least-privilege for pods.

## Prerequisites

- kubectl with cluster-admin access for audit scope
- Kubernetes API access (read-only for audit)
- Python 3.10+ with pykube-ng or kubernetes client library
- RBAC audit tools (kubectl-who-can, rback, krane, polaris)
- CIS Kubernetes Benchmark knowledge
- Cluster configuration and namespace list

## Workflow

1. Enumerate RBAC resources: Collect all ClusterRoles, Roles, ClusterRoleBindings, and RoleBindings across all namespaces
2. Identify cluster-admin users: List all subjects with cluster-admin ClusterRoleBinding or equivalent privileges
3. Analyze privileged permissions: Flag roles with wildcard verbs (*) or resources (pods, secrets, nodes, persistentvolumes)
4. Check for privilege escalation: Identify roles that allow creating/updating Roles or RoleBindings (rbac.authorization.k8s.io)
5. Review service accounts: List all service accounts with associated roles and assess if permissions match pod requirements
6. Audit token mounting: Check pods with automountServiceAccountToken: true and service accounts with privileged roles
7. Validate network policies: Verify pods with sensitive RBAC are restricted by NetworkPolicy for least-network-access
8. Check default service account: Ensure default service account does not have excessive permissions in each namespace
9. Review aggregation rules: Analyze ClusterRole label selectors for unintended role inheritance
10. Generate remediation plan: Recommend permission reductions and role refinements for each RBAC violation

## Verification

- No subjects have cluster-admin privileges unnecessarily
- No roles grant wildcard access to secrets or sensitive resources
- Service accounts follow least privilege (only permissions required for their function)
- Default service accounts in each namespace have no permissions beyond GET on basic resources
- Token automounting is disabled for service accounts that do not need API access
- Network policies restrict egress from privileged service accounts
- RBAC audit is repeatable and integrated into CI/CD pipeline
