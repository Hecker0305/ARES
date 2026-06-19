# Phishing Incident Response Workflows

## User-Reported Phishing
1. User reports via PhishAlarm / Report Message button
2. SOC analyst triages: header analysis, URL/attachment verdict
3. If malicious: extract IOCs, remove from all mailboxes, block indicators
4. User notification sent with awareness guidance
5. Threat intelligence updated with campaign TTPs

## Automated Phishing Detection
1. Email gateway quarantine suspicious messages (high spam score, new domain, spoofed sender)
2. SIEM correlates multiple similar emails as campaign
3. Automated playbook: detonate attachments, scan URLs, remove from mailboxes
4. Analyst reviews automated actions, escalates if needed
