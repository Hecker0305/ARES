# Honeytoken Deployment Workflow

## File Token Deployment
1. Create decoy credential files (passwords.xlsx, aws_keys.csv, db_conn.txt)
2. Place in shared drives, file servers, Git repos
3. Embed web bug or DNS token in each file
4. Monitor for file access via DNS/SIEM alerts

## Cloud Token Deployment
1. Create fake AWS IAM keys with no permissions
2. Place keys in S3 bucket, Lambda env vars, GitHub repos
3. Use GuardDuty or custom Lambda to detect key usage
4. Create fake Azure AD service accounts with sign-in logging

## Database Token Deployment
1. Insert fake rows into production databases
2. Create table with decoy customer data
3. Monitor for SELECT queries on decoy tables
4. Alert on any access to honeytoken data
