# Deep Technical Procedures

## AWS IAM Audit

```bash
# List all IAM users
aws iam list-users --query 'Users[*].UserName' --output table

# Find users with console access but no MFA
aws iam list-users --query 'Users[*].UserName' | \
  xargs -I {} aws iam list-mfa-devices --user-name {} | \
  jq -r '.MFADevices | select(length == 0) | "NO MFA"'

# Identify unused IAM roles (last used > 90 days)
aws iam list-roles --query 'Roles[?RoleLastUsed.LastUsedDate]' | \
  jq '.[] | select(.RoleLastUsed.LastUsedDate < (now - 7776000)) | .RoleName'

# Check for policies with full admin access
aws iam list-policies --scope Local --only-attached | \
  jq -r '.Policies[].Arn' | xargs -I {} aws iam get-policy-version --policy-arn {} \
  --version-id v1 | jq 'select(.PolicyVersion.Document.Statement[].Action == "*") | {arn: .PolicyVersion.Document}'
```

## Azure RBAC Audit

```bash
# List custom role definitions
az role definition list --custom-role-only true --output json | \
  jq '.[] | {name: .roleName, actions: .permissions[].actions}'

# Find privileged role assignments
az role assignment list --include-groups --query \
  "[?contains(properties.roleDefinition.properties.roleName, 'Owner') || \
  contains(properties.roleDefinition.properties.roleName, 'Contributor') || \
  contains(properties.roleDefinition.properties.roleName, 'Admin')]" -o table
```

## GCP IAM Audit

```bash
# Get IAM policy for project
gcloud projects get-iam-policy $PROJECT --format=json | \
  jq '.bindings[] | select(.role | contains("admin") or contains("owner") or contains("editor"))'

# Find service account keys that are too old
gcloud iam service-accounts list --project=$PROJECT --format="value(email)" | \
  xargs -I {} gcloud iam service-accounts keys list --iam-account={} \
  --managed-by=user --format="table(name,validAfterTime,validBeforeTime,keyType)"
```

## Python CIEM Tool

```python
import boto3, json
iam = boto3.client('iam')
users = iam.list_users()['Users']
for user in users:
    policies = iam.list_attached_user_policies(UserName=user['UserName'])
    for policy in policies['AttachedPolicies']:
        version = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
        doc = iam.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=version)
        if '*' in json.dumps(doc['PolicyVersion']['Document']['Statement']):
            print(f"{user['UserName']} has admin policy: {policy['PolicyName']}")
```
