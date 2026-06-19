---
name: ci-cd-security
description: >-
  CI/CD pipeline security hardening covering pipeline-as-code review, secrets management, artifact integrity,
  dependency scanning, deployment gate enforcement, and supply chain attack prevention.
domain: devsecops
subdomain: ci-cd-security
tags: [devsecops, ci-cd, pipeline-security, github-actions, gitlab-ci, jenkins, supply-chain]
mitre_attack: [T1195, T1198, T1525, T1554, T1574]
nist_csf: [PR.AC-1, PR.AC-4, PR.DS-6, PR.IP-3, DE.CM-1, DE.CM-4, DE.CM-8, RS.MI-3]
d3fend: [D3-SBOM, D3-IAV, D3-CICD, D3-SA]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1, MAP-2.2, MANAGE-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during CI/CD platform setup and review, for pipeline security audits, when integrating security testing into development workflows, during supply chain security assessments, and when auditing deployment automation.

## Prerequisites

- CI/CD platform access (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps)
- Repository access with pipeline configuration files
- Secrets management solution (HashiCorp Vault, AWS Secrets Manager, CyberArk)
- SAST/DAST/SCA tools for security test integration (Semgrep, SonarQube, Snyk, Trivy)
- Artifact repository with integrity verification (Artifactory, Nexus, GHCR)
- Python 3.10+ for pipeline security automation and reporting

## Workflow

1. Audit pipeline configuration: Review pipeline YAML/XML files for security misconfigurations (hardcoded secrets, insecure script execution, privileged contexts)
2. Validate secrets management: Ensure all secrets are stored in secrets manager (not in code, logs, or artifacts), verify secret rotation
3. Check artifact integrity: Verify build artifacts are signed, have SBOMs attached, and are scanned before deployment
4. Test dependency scanning: Confirm SCA scanning is in pipeline (fail on critical/high vulnerabilities), check for dependency confusion risks
5. Review deployment gates: Verify approval gates, environment promotion rules, and rollback capabilities are enforced
6. Audit container builds: Verify container image scanning, base image integrity, and minimal image practice in pipeline
7. Check code signing: Validate that builds are signed with trusted certificates and signature verification before deployment
8. Review access controls: Check least-privilege for pipeline service accounts, restrict pipeline execution permissions, and audit pipeline modifications
9. Test supply chain: Analyze third-party actions, plugins, and integrations for potential supply chain risks
10. Implement monitoring: Set up pipeline audit logging, drift detection for pipeline changes, and alerting on security findings

## Verification

- No secrets or credentials are hardcoded in pipeline configs or stored in repository
- Pipeline fails on critical/high SAST or SCA findings (build break configured)
- All deployment artifacts are signed and have SBOMs attached
- Container images are scanned and only non-vulnerable images are deployed
- Pipeline execution uses least-privilege service accounts with scoped permissions
- Third-party actions/plugins are pinned to specific versions and audited for security
- Pipeline audit logging is enabled and changes to pipelines require code review
