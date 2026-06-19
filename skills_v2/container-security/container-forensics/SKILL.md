---
name: container-forensics
description: >-
  Forensic investigation methodology for containerized environments including container image analysis,
  container runtime artifact collection, orchestration log analysis, and incident reconstruction in Kubernetes.
domain: container-security
subdomain: container-forensics
tags: [container-forensics, kubernetes-forensics, docker, containerd, incident-response, cloud-native]
mitre_attack: [T1070, T1525, T1562, T1613]
nist_csf: [DE.AE-2, DE.CM-1, ID.SC-2, PR.DS-1, RS.AN-1, RS.AN-5]
d3fend: [D3-CF, D3-DF, D3-CDR, D3-EDR]
nist_ai_rmf: [MEASURE-2.1, MAP-1.2, RESPOND-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during incident response in containerized environments, when investigating container compromise, for extracting forensic evidence from ephemeral container runtimes, and when reconstructing attack chains in Kubernetes.

## Prerequisites

- kubectl with access to affected cluster and namespace
- Docker or containerd (nerdctl) for container runtime access
- Forensic tools: cri-dockerd, containerd-shim, docker save, skopeo
- Etcdctl for Kubernetes state extraction (if etcd is accessible)
- Python 3.10+ for evidence parsing and timeline creation
- Immutable storage for forensic evidence collection

## Workflow

1. Preserve cluster state: Snapshot Kubernetes objects (pods, deployments, configmaps, secrets, events) before any cleanup: `kubectl get all -n <ns> -o yaml > cluster_state.yaml`
2. Capture container image: Save container image from registry or node for offline analysis: `docker save <image> -o image.tar`
3. Export container logs: Retrieve kubelet logs, container stdout/stderr, and audit logs: `kubectl logs <pod> --all-containers > pod_logs.txt`
4. Extract container filesystem: Use `docker cp` or `nerdctl cp` to copy container filesystem to forensic host
5. Capture runtime artifacts: Collect running process list, network connections, and mounted volumes from host node
6. Analyze container commit: If container is still running, create a forensic image: `docker commit <container> forensic_image`
7. Review Kubernetes events: `kubectl get events -n <ns> --sort-by=.lastTimestamp` to understand event sequence
8. Examine etcd if accessible: Back up etcd snapshot for cluster-level state reconstruction
9. Correlate with orchestrator logs: Analyze kube-controller-manager, kube-scheduler, and API server logs
10. Reconstruct timeline: Build chronological attack timeline from container, orchestrator, and host-level evidence

## Verification

- Container image is preserved with SHA-256 hash verification
- All container logs are exported with timestamps and source identification
- Kubernetes events provide full lifecycle of compromised pods
- Container filesystem is extracted and analyzed for malicious artifacts
- Network connections at time of compromise are documented
- Attack timeline is reconstrucable within 1-minute granularity
- Evidence chain of custody is documented for legal admissibility
