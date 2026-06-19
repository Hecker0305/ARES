#!/usr/bin/env python3
"""Cloud-agnostic IAM Audit Tool"""
import argparse
import json
from datetime import datetime, timedelta

class CIEMManager:
    def __init__(self, provider):
        self.provider = provider
        self.findings = []

    def audit_aws(self):
        import boto3
        iam = boto3.client('iam')
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            mfa = iam.list_mfa_devices(UserName=username)
            if not mfa['MFADevices']:
                self.findings.append({
                    'severity': 'HIGH', 'provider': 'AWS',
                    'resource': f'user/{username}',
                    'finding': 'No MFA device configured for human user'
                })
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                age = (datetime.now() - key['CreateDate'].replace(tzinfo=None)).days
                if age > 90:
                    self.findings.append({
                        'severity': 'MEDIUM', 'provider': 'AWS',
                        'resource': f'user/{username}/key/{key["AccessKeyId"]}',
                        'finding': f'Access key is {age} days old (max 90)'
                    })

    def audit_azure(self):
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
        client = AuthorizationManagementClient(credential, 'subscription')
        for assignment in client.role_assignments.list():
            if 'Owner' in assignment.role_definition_id or 'Contributor' in assignment.role_definition_id:
                self.findings.append({
                    'severity': 'HIGH', 'provider': 'Azure',
                    'resource': f'role/{assignment.name}',
                    'finding': f'High-privilege role assigned to {assignment.principal_id}'
                })

    def audit_gcp(self):
        from google.cloud import resource_manager_v3
        client = resource_manager_v3.ProjectsClient()
        for project in client.search_projects():
            iam_client = resource_manager_v3.IAMPolicyClient()
            policy = iam_client.get_iam_policy(request={'resource': project.name})
            for binding in policy.bindings:
                if 'admin' in binding.role or 'owner' in binding.role.lower():
                    self.findings.append({
                        'severity': 'HIGH', 'provider': 'GCP',
                        'resource': project.project_id,
                        'finding': f'High-privilege binding: {binding.role}'
                    })

    def run(self):
        if self.provider in ('aws', 'all'):
            self.audit_aws()
        if self.provider in ('azure', 'all'):
            self.audit_azure()
        if self.provider in ('gcp', 'all'):
            self.audit_gcp()
        return self.findings

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider', choices=['aws', 'azure', 'gcp', 'all'], required=True)
    args = parser.parse_args()
    manager = CIEMManager(args.provider)
    results = manager.run()
    print(json.dumps(results, indent=2))
