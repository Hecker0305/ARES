---
name: zero-trust-identity
description: >-
  Zero Trust identity architecture implementation covering continuous authentication, adaptive MFA,
  device posture checks, risk-based conditional access, and identity telemetry analysis.
domain: identity-access
subdomain: zero-trust-identity
tags: [zero-trust, identity, continuous-authentication, mfa, conditional-access, device-posture]
mitre_attack: [T1078, T1098, T1133, T1484, T1550, T1556]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-6, PR.AC-7, DE.CM-3, DE.CM-7]
d3fend: [D3-ZTA, D3-IAM, D3-CA, D3-PIM, D3-MFA]
nist_ai_rmf: [GOVERN-1.1, GOVERN-2.3, MEASURE-1.2, MAP-2.1, DETECT-3.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when implementing Zero Trust identity principles, during identity provider modernization, when deploying conditional access policies, for continuous authentication evaluation, and during security architecture review.

## Prerequisites

- Modern identity provider (Azure AD, Okta, Ping Identity, Keycloak)
- Multi-factor authentication solution configured and enrolled
- Device management platform (Intune, JAMF, Workspace ONE) for device compliance
- SIEM for identity telemetry analysis
- API gateway or reverse proxy for policy enforcement
- UEBA platform for risk scoring

## Workflow

1. Identity posture assessment: Evaluate current authentication methods, MFA coverage, and conditional access policies
2. Enforce MFA for all users: Implement risk-based MFA with step-up authentication for sensitive actions
3. Deploy device compliance: Integrate device management with identity provider to check device health (encryption, patch level, jailbreak)
4. Implement conditional access: Create policies based on user, device, location, application, and risk score conditions
5. Enable continuous authentication: Deploy token binding, session risk evaluation, and re-authentication triggers
6. Integrate risk scoring: Combine identity, device, and behavioral risk signals into session risk score
7. Deploy passwordless authentication: Implement FIDO2 security keys, Windows Hello, or biometrics as primary auth
8. Configure session policies: Set token lifetimes based on risk (short-lived for high-risk, longer for trusted)
9. Monitor identity telemetry: Analyze sign-in logs, MFA denials, device enrollment, and privileged role activation
10. Incident response integration: Trigger automatic session revocation and account remediation on identity compromise

## Verification

- MFA is enforced for all external and privileged access (target: 100% enrollment)
- Conditional access policies block non-compliant devices from accessing corporate data
- Risk-based policies automatically trigger requiring MFA or blocking access for high-risk sessions
- Passwordless authentication covers >= 50% of users within first 6 months
- Continuous authentication terminates sessions on risk score increase
- Identity incident response playbook executes automatically on compromise indicators
