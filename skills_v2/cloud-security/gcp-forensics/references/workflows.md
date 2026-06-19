# Deep Technical Procedures

## Instance Isolation Procedure

```bash
# Step 1: Remove public IP and add network isolation tag
INSTANCE="compromised-instance"
ZONE="us-central1-a"
PROJECT="target-project"

gcloud compute instances delete-access-config $INSTANCE --zone=$ZONE \
  --access-config-name="external-nat"

gcloud compute instances add-tags $INSTANCE --tags=forensic-isolation --zone=$ZONE

# Step 2: Apply blocking firewall rule
gcloud compute firewall-rules create forensic-block-egress \
  --network=default --direction=EGRESS --priority=100 \
  --target-tags=forensic-isolation --destination-ranges=0.0.0.0/0 --action=DENY
```

## Disk Forensic Acquisition

```bash
# Create forensic snapshot
gcloud compute disks snapshot $INSTANCE-disk --zone=$ZONE \
  --snapshot-names=case-001-snapshot --description="Forensic acquisition $(date -u)"

# Validate snapshot hash
gcloud compute snapshots describe case-001-snapshot --format="value(name,diskSizeGb,status,sourceDisk)"

# Clone to forensic project
gcloud compute disks create forensic-disk-clone \
  --source-snapshot=case-001-snapshot --zone=forensic-zone \
  --project=forensic-project --type=pd-ssd
```

## Audit Log Analysis

```bash
# Query for IAM policy changes
gcloud logging read 'protoPayload.methodName="SetIamPolicy" AND resource.type="project"' \
  --project=$PROJECT --format="json" --limit=50 | jq '.[].protoPayload | {method: .methodName, user: .authenticationInfo.principalEmail, time: .timestamp}'
```

## Python Forensic Assistant

```python
from google.cloud import compute_v1
from google.cloud import logging_v2

def collect_forensic_evidence(project_id, instance_name, zone):
    disks_client = compute_v1.DisksClient()
    instances_client = compute_v1.InstancesClient()
    logging_client = logging_v2.LoggingClientV2()

    instance = instances_client.get(project=project_id, zone=zone, instance=instance_name)
    evidence = {
        'instance_id': instance.id,
        'creation_timestamp': instance.creation_timestamp,
        'disks': [],
        'logs': []
    }
    for disk in instance.disks:
        snapshot = disks_client.snapshot(
            project=project_id, zone=zone,
            disk=disk.source.split('/')[-1],
            snapshot_resource={'name': f'forensic-{instance.id}-{disk.index}'}
        )
        evidence['disks'].append({'disk': disk.source, 'snapshot': snapshot.name})
    return evidence
```
