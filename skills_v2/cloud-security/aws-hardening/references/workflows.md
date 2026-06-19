# Deep Technical Procedures

## Automated CIS Compliance Scanner

### Procedure: Full Account Scan
```bash
python aws_cis_scanner.py --profile production --regions all --output json --severity CRITICAL,HIGH
```

### IAM Policy Review
```bash
# Identify overly permissive policies
aws iam list-policies --scope Local --query 'Policies[?PermissionsBoundaryUsageCount==`0`].{Name:PolicyName,Arn:Arn}' --output table

# Check for unused IAM roles
aws iam list-roles --query 'Roles[?RoleLastUsed==null].RoleName' --output table
```

### S3 Bucket Audit
```bash
# Check public access blocks on all buckets
aws s3api list-buckets --query 'Buckets[*].Name' | xargs -I {} aws s3api get-public-access-block --bucket {}
```

### CloudTrail Validation
```bash
# Validate trail configuration across all regions
aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`].{Name:Name,S3BucketName:S3BucketName,LogFileValidationEnabled:LogFileValidationEnabled}' --output table
```

## Remediation Playbook

### IAM Key Rotation
1. Identify keys older than 90 days: `aws iam list-access-keys --user-name <user> --query 'AccessKeyMetadata[?Status==`Active`].[AccessKeyId,CreateDate]'`
2. Create new access key
3. Update applications with new key
4. Mark old key as Inactive
5. Verify application functionality
6. Delete old key after 24 hour cooldown

### S3 Public Access Block
```python
import boto3
s3control = boto3.client('s3control')
s3control.put_public_access_block(
    AccountId='123456789012',
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
    }
)
```
