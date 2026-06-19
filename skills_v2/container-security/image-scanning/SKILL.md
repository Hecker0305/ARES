---
name: image-scanning
description: >-
  Container image vulnerability scanning in CI/CD pipelines covering registry integration, vulnerability
  severity assessment, base image hardening, SBOM generation, and admission control enforcement.
domain: container-security
subdomain: image-scanning
tags: [container, image-scanning, vulnerabilities, sbom, supply-chain, docker, trivy, snyk]
mitre_attack: [T1190, T1204, T1525, T1613]
nist_csf: [ID.RA-1, ID.RA-2, DE.CM-1, DE.CM-4, PR.DS-6, RS.MI-3]
d3fend: [D3-CR, D3-SA, D3-VM, D3-IAV]
nist_ai_rmf: [MEASURE-2.1, MAP-1.2, GOVERN-3.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when integrating container security into CI/CD pipelines, during container registry configuration, for vulnerability management of container images, when auditing base image choices, and during supply chain security reviews.

## Prerequisites

- Container registry (Docker Hub, ECR, ACR, GCR, Harbor)
- Image scanning tools (Trivy, Snyk, Grype, Clair, Anchore)
- CI/CD platform (GitHub Actions, GitLab CI, Jenkins, Argo Workflows)
- Kubernetes admission controller (OPA/Gatekeeper, Kyverno)
- Python 3.10+ for vulnerability aggregation and reporting
- SBOM generation tools (Syft, SPDX)

## Workflow

1. Configure registry scanning: Enable automatic scanning on image push for all container registries
2. Define vulnerability policies: Set severity thresholds (e.g., block CRITICAL + fixable, warn on HIGH)
3. Scan base images: Baseline all base images and identify outdated/minimal alternatives (Alpine, Distroless)
4. Generate SBOM: `syft <image> -o spdx-json > sbom.json` for supply chain transparency
5. Implement CI/CD gate: Add scanning step to pipeline that fails on policy violations
6. Manage exceptions: Process vulnerability exceptions with documented risk acceptance
7. Run admission control: Deploy admission controller (Kyverno, OPA) to block non-compliant images at deploy time
8. Monitor runtime: Scan running containers for drift from scanned image (new packages, modified binaries)
9. Track remediation: Create Jira tickets or PRs for vulnerability remediation with automated fix versions
10. Report metrics: Track vulnerability counts, MTTR, exception rates, and compliance over time

## Verification

- All images in registry are scanned and vulnerability data is accessible
- CI/CD pipeline blocks image promotion when vulnerabilities exceed policy threshold
- SBOM is generated and attached to each image build
- Admission controller enforces scan policy at deploy time (verify-enforce)
- Base images are less than 30 days old and use minimal footprint
- Runtime drift detection alerts on unapproved package additions
- Vulnerability dashboard shows trends, top CVEs, and remediation progress
