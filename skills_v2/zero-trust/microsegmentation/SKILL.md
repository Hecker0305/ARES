---
name: microsegmentation
description: >-
  Zero trust network microsegmentation methodology covering workload-level segmentation, service mesh implementation,
  Kubernetes network policies, cloud VPC segmentation, and identity-based firewall rules.
domain: zero-trust
subdomain: microsegmentation
tags: [microsegmentation, zero-trust, network-segmentation, service-mesh, kubernetes-network-policy, workload]
mitre_attack: [T1048, T1090, T1557]
nist_csf: [PR.AC-4, PR.AC-5, PR.PT-3, de.cm-1, de.cm-4]
d3fend: [D3-SG, D3-MICRO, D3-SM, D3-NACL]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during zero trust network segmentation implementation, for Kubernetes microsegmentation with network policies, when deploying service mesh with mTLS, and during workload-to-workload access control design.

## Prerequisites

- Kubernetes cluster with CNI supporting Network Policies (Calico, Cilium, Weave)
- Service mesh (Istio, Linkerd, Consul) for identity-based workload segmentation
- Cloud VPC and security group access for cloud workload segmentation
- Workload dependency mapping (service-to-service communication flows)
- Kubernetes RBAC configuration access
- Understanding of workload identity (K8s service accounts, SPIFFE)

## Workflow

1. Map workload dependencies: Identify all workload-to-workload communication (service, port, protocol) using TrafficFlow or similar service dependency mapping
2. Define microsegmentation policies: Create Kubernetes NetworkPolicy rules per namespace specifying allowed ingress/egress based on pod selector and ports
3. Implement least-privilege network: Default deny all ingress/egress, allow only identified dependencies
4. Enable mTLS for service mesh: Deploy Istio/Linkerd with mTLS strict mode for workload-to-workload authentication
5. Label workloads with identity: Apply consistent labels to workloads for policy attachment (app, tier, compliance)
6. Enforce network policies in CI/CD: Add NetworkPolicy validation to CI/CD pipeline (deny if policy missing)
7. Implement cloud segmentation: Use VPC network ACLs and security groups aligned with workload identity
8. Monitor segmentation gaps: Track pods without NetworkPolicy, services with allow-all policies, drift from baseline
9. Test segmentation: Run connectivity tests between workload pairs to validate only intended traffic is allowed
10. Automate policy management: Generate and update NetworkPolicies from service dependency graphs and deployment manifests

## Verification

- All namespaces have default-deny ingress NetworkPolicy (no pods accept unexpected traffic)
- All pods have explicit egress NetworkPolicy (no unexpected outbound connections)
- Service mesh mTLS is in STRICT mode (no plaintext traffic between workloads)
- Workload identity (SPIFFE certs) is used for authentication between services
- CI/CD pipeline blocks deployments without NetworkPolicy manifest
- Connectivity tests confirm only intended traffic flows between workloads
- Segmentation coverage is > 95% of workloads
- Microsegmentation policy changes require RBAC approval
