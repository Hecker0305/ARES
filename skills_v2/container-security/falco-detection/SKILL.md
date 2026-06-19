---
name: falco-detection
description: >-
  Runtime security detection with Falco for Kubernetes environments. Covers custom rule creation,
  syscall monitoring, container drift detection, and response automation via Falco Sidekick.
domain: container-security
subdomain: falco-detection
tags: [falco, container-security, runtime-detection, syscall-monitoring, k8s, cloud-native]
mitre_attack: [T1059, T1078, T1133, T1525, T1550, T1562, T1613]
nist_csf: [DE.AE-2, DE.CM-1, DE.CM-3, DE.CM-4, DE.CM-7, PR.PT-1]
d3fend: [D3-HID, D3-NDR, D3-EDR, D3-CDR]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-1.3, MONITOR-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when deploying runtime security monitoring for Kubernetes, detecting container breakouts and unusual syscall patterns, creating custom Falco rules for specific threats, and integrating Falco alerts with SIEM/SOAR.

## Prerequisites

- Falco deployed on all Kubernetes nodes (DaemonSet) with kernel module or eBPF driver
- Falcosidekick for alert forwarding to SIEM/SOAR
- Kubernetes audit log integration
- Access to Falco rule files (/etc/falco/falco_rules.yaml)
- Understanding of Linux syscalls and container security contexts
- SIEM/SOAR for alert aggregation

## Workflow

1. Deploy Falco: Install via Helm chart on Kubernetes with eBPF probe for kernel compatibility
2. Verify installation: Confirm Falco pods are running and processing events (`falco --list`)
3. Enable default rules: Configure base ruleset (shell in container, privileged container, unexpected outbound)
4. Monitor alerts: Review default rule alerts in SIEM for 7 days to understand baseline events
5. Tune rules: Add exceptions to reduce false positives from legitimate administrative activity
6. Create custom rules: Develop specialized rules for application-specific threats (e.g., database dump, cryptomining patterns)
7. Integrate with Falcosidekick: Configure alert output to Slack, SIEM, SOAR, or cloud function
8. Implement response: Create automated responses (kill pod, isolate node, snapshot container) based on rule priority
9. Audit Kubernetes audit logs: Enable K8s audit log analysis for API-level detections (RBAC abuse, configmap secrets)
10. Test detection: Execute red team container scenarios to validate rule coverage and response automation

## Verification

- Falco DaemonSet is running on all nodes with successful driver initialization
- Default rules generate alerts for shell access, privilege escalation, and suspicious syscalls
- Custom rules are tailored to application-specific behaviors and FP-tuned
- Falcosidekick delivers alerts to SIEM within 5 seconds
- Automated response playbooks execute correctly on test scenarios
- Rule coverage maps to MITRE ATT&CK container techniques
