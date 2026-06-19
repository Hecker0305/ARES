# Standards Reference

## MITRE ATT&CK Mappings

- T1525: Cloud Infrastructure Discovery - Enumerate cloud resources to identify misconfigurations
- T1530: Data from Cloud Storage - S3 bucket data exposure via misconfigurations
- T1613: Container and Resource Discovery - Container registry and resource enumeration

## NIST CSF v1.1 Mappings

- DE.CM-1: Monitoring for unauthorized personnel, connections, devices, and software
- DE.CM-7: Monitoring for unauthorized cloud resource modifications
- ID.AM-1: Physical devices and systems within the organization are inventoried
- PR.AC-1: Identities and credentials are managed for authorized devices and users
- PR.DS-1: Data-at-rest is protected
- PR.PT-3: Access to cloud resources is managed

## CIS AWS Foundations Benchmark v2.0

### Level 1 (Automated)
- 1.1: Avoid the use of root account (Score: 5)
- 1.2: Enable MFA for root account (Score: 5)
- 1.3: Enable audit logging (Score: 5)
- 1.4: Configure CloudTrail (Score: 5)
- 2.1: Ensure S3 Block Public Access is enabled (Score: 10)

### Level 2 (Manual/Advanced)
- 3.1: Ensure IAM policies are attached only to groups or roles (Score: 8)
- 4.1: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Score: 8)

## D3FEND Countermeasures

- D3-HN: Honeynet deployment for cloud network detection
- D3-CA: Cloud Access Security Broker integration
- D3-IAM: Identity and Access Management controls
- D3-ENC: Encryption at rest and in transit

## References

- CIS AWS Foundations Benchmark v2.0: https://www.cisecurity.org/benchmark/amazon_web_services
- AWS Well-Architected Framework: https://docs.aws.amazon.com/wellarchitected/latest/framework
- NIST SP 800-53 Rev. 5 Cloud Controls: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
