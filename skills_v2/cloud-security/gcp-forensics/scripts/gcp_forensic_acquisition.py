#!/usr/bin/env python3
"""GCP Forensic Evidence Acquisition Tool"""
import argparse
import hashlib
import json
from datetime import datetime
from google.cloud import compute_v1, storage, logging_v2

class GCPForensicAcquisition:
    def __init__(self, project_id, case_id):
        self.project_id = project_id
        self.case_id = case_id
        self.instances = compute_v1.InstancesClient()
        self.disks = compute_v1.DisksClient()
        self.snapshots = compute_v1.SnapshotsClient()
        self.storage = storage.Client()
        self.logging = logging_v2.LoggingServiceV2Client()
        self.evidence = {'case': case_id, 'acquisitions': []}

    def snapshot_instance_disk(self, instance_name, zone):
        instance = self.instances.get(project=self.project_id, zone=zone, instance=instance_name)
        for disk in instance.disks:
            disk_name = disk.source.split('/')[-1]
            snapshot_name = f'{self.case_id}-{disk_name}-{datetime.now().strftime("%Y%m%d%H%M%S")}'
            op = self.disks.snapshot(
                project=self.project_id, zone=zone, disk=disk_name,
                snapshot_resource={
                    'name': snapshot_name,
                    'description': f'Forensic acquisition for case {self.case_id}'
                }
            )
            op.result()
            snapshot = self.snapshots.get(project=self.project_id, snapshot=snapshot_name)
            self.evidence['acquisitions'].append({
                'type': 'disk_snapshot',
                'disk': disk_name,
                'snapshot': snapshot_name,
                'size_gb': snapshot.disk_size_gb,
                'status': snapshot.status,
                'timestamp': datetime.now().isoformat()
            })

    def export_audit_logs(self, days=7):
        from google.protobuf import timestamp_pb2
        import operator

        now = datetime.utcnow()
        delta = timestamp_pb2.Timestamp()
        delta.FromDatetime(now)
        start_time = timestamp_pb2.Timestamp()
        start_time.FromDatetime(now).FromDatetime(now.replace(day=now.day - days))

        filter_str = f'resource.type="gce_instance" AND severity>=WARNING AND timestamp>="{start_time.ToJsonString()}"'
        entries = self.logging.list_log_entries(
            resource_names=[f'projects/{self.project_id}'],
            filter_=filter_str
        )
        for entry in entries:
            self.evidence['acquisitions'].append({
                'type': 'audit_log',
                'timestamp': entry.timestamp.ToJsonString(),
                'severity': entry.severity.name,
                'principal': entry.proto_payload.authentication_info.principal_email if entry.proto_payload else 'N/A',
                'method': entry.proto_payload.method_name if entry.proto_payload else 'N/A'
            })

    def generate_evidence_hash(self):
        evidence_str = json.dumps(self.evidence, default=str, sort_keys=True)
        return hashlib.sha256(evidence_str.encode()).hexdigest()

    def run(self, instance_name, zone):
        self.snapshot_instance_disk(instance_name, zone)
        self.export_audit_logs()
        self.evidence['chain_of_custody_hash'] = self.generate_evidence_hash()
        return json.dumps(self.evidence, indent=2, default=str)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--project-id', required=True)
    parser.add_argument('--case-id', required=True)
    parser.add_argument('--instance', required=True)
    parser.add_argument('--zone', required=True)
    args = parser.parse_args()
    acq = GCPForensicAcquisition(args.project_id, args.case_id)
    print(acq.run(args.instance, args.zone))
