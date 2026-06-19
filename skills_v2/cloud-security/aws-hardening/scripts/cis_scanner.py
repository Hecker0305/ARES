#!/usr/bin/env python3
"""CIS AWS Foundations Benchmark Scanner"""
import boto3
import json
import argparse
from datetime import datetime

class CISSanner:
    def __init__(self, profile, region):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = session.client('iam')
        self.s3 = session.client('s3')
        self.cloudtrail = session.client('cloudtrail')
        self.ec2 = session.client('ec2')
        self.kms = session.client('kms')
        self.findings = []

    def check_password_policy(self):
        try:
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            checks = {
                'MinimumPasswordLength >= 14': policy.get('MinimumPasswordLength', 0) >= 14,
                'RequireUppercase': policy.get('RequireUppercaseCharacters', False),
                'RequireLowercase': policy.get('RequireLowercaseCharacters', False),
                'RequireNumbers': policy.get('RequireNumbers', False),
                'RequireSymbols': policy.get('RequireSymbols', False),
                'PasswordReusePrevention': policy.get('PasswordReusePrevention', 0) >= 24,
            }
            for check, passed in checks.items():
                if not passed:
                    self.findings.append({'check': check, 'status': 'FAIL', 'resource': 'iam-password-policy'})
        except Exception:
            self.findings.append({'check': 'PasswordPolicy', 'status': 'NO_POLICY', 'resource': 'iam-password-policy'})

    def check_s3_public_access(self):
        buckets = self.s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            try:
                config = self.s3.get_public_access_block(Bucket=bucket['Name'])
                pab = config['PublicAccessBlockConfiguration']
                if not all([pab.get('BlockPublicAcls'), pab.get('IgnorePublicAcls'),
                           pab.get('BlockPublicPolicy'), pab.get('RestrictPublicBuckets')]):
                    self.findings.append({'check': 'S3 Public Access Block', 'status': 'FAIL', 'resource': f's3://{bucket["Name"]}'})
            except Exception:
                self.findings.append({'check': 'S3 Public Access Block', 'status': 'NOT_CONFIGURED', 'resource': f's3://{bucket["Name"]}'})

    def run(self):
        self.check_password_policy()
        self.check_s3_public_access()
        return self.findings

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', required=True)
    parser.add_argument('--region', default='us-east-1')
    args = parser.parse_args()
    scanner = CISSanner(args.profile, args.region)
    results = scanner.run()
    print(json.dumps(results, indent=2))
