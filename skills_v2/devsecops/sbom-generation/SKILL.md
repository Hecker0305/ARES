---
name: sbom-generation
description: >-
  Software Bill of Materials generation methodology for supply chain security. Covers SBOM creation using Syft and SPDX,
  CycloneDX formats, dependency tree analysis, vulnerability correlation, and CI/CD integration.
domain: devsecops
subdomain: sbom-generation
tags: [sbom, spdx, cyclonedx, supply-chain, dependency-management, syft, devsecops]
mitre_attack: [T1195, T1198]
nist_csf: [ID.RA-1, ID.RA-2, PR.DS-6, de.cm-1, de.cm-4]
d3fend: [D3-SBOM, D3-IAV, D3-SA]
nist_ai_rmf: [GOVERN-1.2, MAP-1.1, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during software supply chain security program implementation, when generating SBOMs for compliance (EO 14028, NTIA), when integrating SBOM generation into CI/CD pipelines, and for vulnerability correlation against component inventories.

## Prerequisites

- SBOM generation tools (Syft, Trivy, CycloneDX Generator, SPDX tools)
- Access to application source code and dependency manifests (package.json, pom.xml, requirements.txt, go.mod, Gemfile)
- Container images for containerized applications
- CI/CD pipeline for automated SBOM generation
- SBOM database or repository for storage and querying
- Grype or Trivy for SBOM vulnerability correlation
- Understanding of SPDX 2.3 and CycloneDX 1.5 specification formats

## Workflow

1. Install SBOM tools: Install Syft and Grype/Trivy on build agents for SBOM generation and vulnerability scanning
2. Generate SBOM for applications: Run `syft <source> -o spdx-json` for application codebases to produce SPDX format SBOM
3. Generate SBOM for containers: Run `syft <image> -o cyclonedx-json` for container images to produce CycloneDX format SBOM
4. Verify SBOM completeness: Validate that all dependencies are captured (including transitive dependencies), check for package name, version, and license fields
5. Correlate vulnerabilities: Run `grype <sbom>` to map SBOM components to known CVEs from vulnerability databases
6. Store SBOMs: Store generated SBOMs in artifact repository alongside builds, indexed by artifact version
7. Integrate into CI/CD: Add SBOM generation step to pipeline after build, before artifact publication
8. Attach SBOM to releases: Include SBOM file with release artifacts for downstream consumers
9. Sign SBOMs: Digitally sign SBOM files for authenticity verification using cosign or GPG
10. Automate compliance: Check SBOM completeness and vulnerability severity thresholds as pipeline gates

## Verification

- SBOM covers all direct and transitive dependencies for each component
- SBOM format is valid SPDX 2.3 or CycloneDX 1.5 (validated against schema)
- Vulnerability correlation identifies all CVEs affecting dependencies with severity scores
- SBOMs are generated for every build and stored with version linkage
- SBOMs are signed and signature is verifiable
- Pipeline gate rejects builds where vulnerabilities exceed policy threshold
- SBOM can be imported into vulnerability management tools for tracking
- License compliance is checked from SBOM data (copyleft, restricted licenses)
