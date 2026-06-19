---
name: ios-analysis
description: >-
  iOS application security testing methodology covering IPA analysis, Mach-O binary review, runtime analysis,
  insecure data storage detection, certificate pinning bypass, and jailbreak detection testing.
domain: mobile-security
subdomain: ios-analysis
tags: [ios, mobile-security, ipa, objective-c, swift, keychain, jailbreak-detection, frida]
mitre_attack: [T1204, T1410, T1418, T1425, T1475]
nist_csf: [PR.AC-4, PR.DS-1, PR.DS-2, de.cm-1]
d3fend: [D3-RP, D3-SB, D3-IAV]
nist_ai_rmf: [DETECT-1.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during iOS mobile app security testing, for IPA binary analysis, when assessing iOS data protection and Keychain security, and during mobile app store review preparation.

## Prerequisites

- macOS with Xcode and Command Line Tools
- Jailbroken iPhone (iOS 15+) for dynamic analysis with Frida
- IPA decryption tool (Clutch, frida-ios-dump, Bagbak) for App Store apps
- Hopper Disassembler or Ghidra for Mach-O binary analysis
- Burp Suite with CA certificate installed on iOS device
- Python 3.10+ with frida-tools for dynamic instrumentation
- Understanding of iOS security model (Keychain, Data Protection Classes, Sandbox, Entitlements, Code Signing)

## Workflow

1. IPA acquisition: Decrypt App Store IPA using frida-ios-dump or obtain development IPA, verify bundle integrity
2. Static binary analysis: Analyze Mach-O binary with Hopper/Ghidra for hardcoded secrets, insecure API usage, and obfuscation assessment
3. Entitlement and plist review: Extract Entitlements.plist and Info.plist for sensitive capabilities and configuration
4. Data storage analysis: Check NSUserDefaults, CoreData, SQLite, Keychain, Cache, and Documents directory for plaintext sensitive data
5. Keychain analysis: Dump Keychain items using Frida or Keychain-dumper, review access control and accessibility attributes
6. Network security: Configure Burp Suite proxy, test HTTPS interception with certificate pinning bypass, check ATS (App Transport Security) configuration
7. Jailbreak detection bypass: Use Frida or Substrate to bypass jailbreak detection, SSL pinning, and anti-debugging checks
8. Runtime analysis: Hook methods with Frida to trace data flow, bypass authentication, and manipulate runtime behavior
9. Local authentication testing: Test FaceID/TouchID, keychain biometric protection, and local authentication bypass
10. Report findings: Document vulnerabilities with proof of concept, code-level remediation, and App Store review guidance

## Verification

- IPA binary is decrypted and decompiled with code review completed
- Keychain items have appropriate accessibility (kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
- No sensitive data stored in NSUserDefaults, Plists, or CoreData in plaintext
- ATS is enabled (NSAllowsArbitraryLoads not set to YES)
- Certificate pinning prevents interception without bypass
- Jailbreak detection prevents execution on jailbroken devices
- Biometric authentication cannot be bypassed through runtime manipulation
- TouchID/FaceID uses localized authentication (not system passcode fallback)
