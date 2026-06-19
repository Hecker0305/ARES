# Canary Token Types and Deployment

## DNS Canary Tokens
1. Generate unique subdomain via canarytokens.org
2. Embed in documents, config files, credential files
3. Monitor DNS logs for token resolution
4. Alert on any DNS query to canary domain

## Web Bug Canary Tokens
1. Generate URL with unique token ID
2. Embed as 1x1 pixel image in documents
3. Deploy in email signatures, internal wikis
4. Alert on HTTP request to canary URL

## Cloud Canary Tokens
1. Deploy fake AWS S3 bucket with public access
2. Generate fake API keys with monitoring
3. Deploy fake Lambda functions with triggers
4. Alert on any resource access attempt

## Network Canary Deployment
1. Configure Thinkst Canary device on network segment
2. Enable decoy services (DNS, HTTP, SMB, RDP)
3. Configure SMTP/SNMP alert forwarding
4. Set up daily health checks via Canary console
