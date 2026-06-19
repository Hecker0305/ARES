# Standards Reference

## Diamond Model Elements
- **Adversary**: The threat actor/group conducting the operation
- **Capability**: Tools, techniques, malware, exploits used
- **Infrastructure**: IPs, domains, servers, certificates used
- **Victim**: Target organization, industry, geography

## Diamond Model Meta-Features
- **Social-Political**: Motivation, intent, ideology
- **Technology**: Sophistication, tooling, TTP maturity
- **Temporal**: Timing, duration, frequency of operations

## Analytic Confidence Levels
| Level | Description |
|-------|-------------|
| High | Strong technical evidence, multiple independent sources, code-level matches |
| Medium | Moderate evidence with corroborating TTP and infrastructure overlaps |
| Low | Behavioral similarity only, limited unique identifiers |
| Unattributed | Insufficient evidence for any confidence assessment |

## Key Analysis Frameworks
- MITRE ATT&CK: Tactic-Technique-Procedure mapping
- Cyber Kill Chain: Recon > Weaponize > Deliver > Exploit > Install > C2 > Actions
- STIX 2.1 Intrusion Set: Structured threat actor representation
- VERIS: Vocabulary for Event Recording and Incident Sharing

## References
- Diamond Model: https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf
- ATT&CK Groups: https://attack.mitre.org/groups/
- MISP Galaxy Clusters: https://www.misp-project.org/galaxy.html
