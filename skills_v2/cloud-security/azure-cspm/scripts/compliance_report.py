#!/usr/bin/env python3
"""Azure Security Posture Compliance Report Generator"""
import argparse
import json
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter

def generate_compliance_report(subscription_id, output_format='json'):
    credential = DefaultAzureCredential()
    sec_client = SecurityCenter(credential, subscription_id)

    report = {
        'subscription_id': subscription_id,
        'scan_date': datetime.utcnow().isoformat(),
        'assessments': [],
        'summary': {'passed': 0, 'failed': 0, 'total': 0}
    }

    assessments = sec_client.assessments.list(subscription_id)
    for assessment in assessments:
        entry = {
            'name': assessment.display_name,
            'status': assessment.status.code,
            'severity': assessment.metadata.severity if assessment.metadata else 'Unknown',
            'description': assessment.metadata.description if assessment.metadata else ''
        }
        report['assessments'].append(entry)
        if assessment.status.code == 'Healthy':
            report['summary']['passed'] += 1
        else:
            report['summary']['failed'] += 1
        report['summary']['total'] += 1

    if output_format == 'json':
        print(json.dumps(report, indent=2, default=str))
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--subscription-id', required=True)
    parser.add_argument('--output', choices=['json', 'pdf'], default='json')
    args = parser.parse_args()
    generate_compliance_report(args.subscription_id, args.output)
