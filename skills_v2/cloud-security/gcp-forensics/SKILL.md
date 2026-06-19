---
name: gcp-forensics
description: >-
  Cloud forensic investigation methodology for Google Cloud Platform incidents.
  Covers compute snapshot acquisition, VPC flow log analysis, Cloud Audit Logs review, and persistent disk forensic imaging.
domain: cloud-security
subdomain: gcp-forensics
tags: [gcp, forensics, cloud, incident-response, compute, storage, logging]
mitre_attack: [T1070, T1562, T1578, T1059]
nist_csf: [DE.CM-1, DE.AE-2, ID.SC-2, PR.PT-1, RS.AN-1, RS.AN-5, RS.MI-2]
d3fend: [D3-FA, D3-LA, D3-ART, D3-CDR]
nist_ai_rmf: [MEASURE-3.1, GOVERN-2.4, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during GCP incident response when there is suspected compromise of a compute instance, data exfiltration, or unauthorized access to GCP resources. Use for both live response (acquiring memory/snapshots from running instances) and post-mortem (analyzing preserved artifacts).

## Prerequisites

- gcloud CLI authenticated with Security Admin or IAM Admin role
- Organization-level access for Org Policy and Audit Log review
- Python 3.10+ with google-cloud-compute, google-cloud-logging, and google-cloud-storage
- Sufficient GCP quota for snapshot creation and disk cloning
- Access to a forensic analysis project with isolated VPC
- jq and yq for log parsing

## Workflow

1. Isolate compromised instance: Replace network tags, remove public IP, and apply VPC firewall rule to block egress
2. Acquire forensic snapshot: `gcloud compute disks snapshot <disk> --zone=<zone> --snapshot-names=<case-id>`
3. Capture memory (if accessible): Use LiME or AVML on the instance and upload to Cloud Storage
4. Clone persistent disk to forensic project: `gcloud compute disks create <clone> --source-snapshot=<snapshot> --zone=<forensic-zone>`
5. Enable Cloud Audit Logs data access logs for the affected project: `gcloud logging sinks create`
6. Export VPC Flow Logs to BigQuery for analysis
7. Analyze IAM policy changes: Work through Cloud Asset Inventory to identify configuration drift
8. Review serial console logs: `gcloud compute instances get-serial-port-output <instance> --zone=<zone>`
9. Examine Cloud Logging for suspicious API calls, identity changes, and data access patterns
10. Document chain of custody and generate forensic timeline

## Verification

- Confirm forensic snapshots are preserved with hash verification (SHA-256)
- Validate Cloud Audit Logs are exported to a secure, immutable bucket
- Verify timeline of events reconstructed with 5-minute granularity
- Confirm disk clones are mounted in isolated forensic environment
- Check that original instance is preserved in its compromised state for legal hold
- Validate all acquired evidence has documented chain of custody
