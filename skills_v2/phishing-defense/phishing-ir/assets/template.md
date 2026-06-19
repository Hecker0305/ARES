# Phishing Incident Report Template

## Incident Details
- Case ID: {{case_id}}
- Date/Time Reported: {{timestamp}}
- Reporter: {{reporter_email}}
- Phishing Type: [Credential Harvesting / Malware Delivery / BEC / Spear Phishing]

## Email Metadata
- From: {{from_address}}
- Subject: {{email_subject}}
- SPF: [pass/fail]
- DKIM: [pass/fail]
- DMARC: [pass/fail]

## IOC Summary
- URLs: {{url_count}}
- Attachments: {{attachment_count}}
- Domains: {{domain_count}}

## Triage Verdict
- Verdict: [Clean / Suspicious / Malicious]
- Confidence: [Low / Medium / High]
- Escalated to: {{escalation_team}}

## Remediation Actions
- [ ] Email removed from all mailboxes
- [ ] URLs blocked on web gateway
- [ ] Hashes blocked on EDR
- [ ] Sender blocked on email gateway
- [ ] User notified
- [ ] Threat intel updated
