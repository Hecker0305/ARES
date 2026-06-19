---
name: social-engineering
description: >-
  Social engineering attack methodology for red team operations covering pretext development, elicitation,
  vishing (voice phishing), SMiShing (SMS phishing), pretexting, and rapport-building techniques.
domain: red-teaming
subdomain: social-engineering
tags: [social-engineering, pretexting, vishing, smishing, elicitation, red-team]
mitre_attack: [T1192, T1193, T1204, T1534, T1566]
nist_csf: [PR.AT-1, PR.AT-2, de.cm-1, de.cm-3]
d3fend: [D3-PHISH, D3-SEG]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1, DETECT-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during red team operations targeting human vectors, for testing security awareness effectiveness, when pretexting for physical access or information gathering, and during OSINT-supported social engineering campaigns.

## Prerequisites

- VoIP phone number for vishing (Google Voice, Twilio, burner phone)
- SMS gateway for SMiShing (Twilio, AWS SNS, burner phone)
- Social media presence (LinkedIn, Facebook) for pretext research
- OSINT tools for target research (Maltego, theHarvester, Sherlock)
- Voicemail system for callback scenarios
- Pretext documentation in Rules of Engagement
- Psychological understanding of influence principles (Cialdini: reciprocity, authority, social proof)

## Workflow

1. OSINT target research: Gather information about targets from LinkedIn, corporate websites, social media, and data breaches
2. Develop pretext: Create convincing persona matching target context (IT support, vendor, executive assistant, HR), supported by fabricated online presence
3. Establish contact method: Select appropriate channel (email, phone, SMS, social media) based on target role and context
4. Execute vishing: Call target under pretext with authority-based framing (urgent security update, executive request)
5. Execute SMiShing: Send SMS messages with contextual hooks (package delivery, HR benefit update, authentication alert)
6. Apply elicitation techniques: Use conversational techniques (bracketing, presumption, artificial ignorance) to extract information
7. Harvest information: Collect credentials, internal data, network information, or access codes
8. Escalate if needed: Use harvested information for subsequent attacks against higher-value targets
9. Document success metrics: Track which pretexts, channels, and techniques achieve operational goals
10. Provide awareness feedback: Deliver targeted training to compromised individuals without singling them out

## Verification

- Pretext is convincing enough to pass initial validation (call-back verification) if triggered
- Target provides at least one piece of sensitive information (credential, access code, internal data)
- Attack achieves operational objective (access, information, credential harvest)
- Social engineering attempt is not reported to security (or reporting time is measured for awareness metrics)
- Multiple targets across different departments are engaged for representative data
- All engagements are documented for awareness program improvement
