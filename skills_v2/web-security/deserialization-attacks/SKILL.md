---
name: deserialization-attacks
description: >-
  Insecure deserialization vulnerability testing across Java, PHP, .NET, Python, Ruby, and Node.js runtimes.
  Covers gadget chain identification, payload generation, RCE exploitation, and detection via instrumentation.
domain: web-security
subdomain: deserialization-attacks
tags: [deserialization, rce, java, php, python, .net, gadget-chains, ysoserial]
mitre_attack: [T1059, T1068, T1190, T1203, T1210]
nist_csf: [PR.AC-4, PR.DS-2, DE.CM-4, DE.CM-8, RS.MI-3]
d3fend: [D3-WAF, D3-SAN, D3-ALR]
nist_ai_rmf: [DETECT-2.2, MEASURE-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during web application security assessments where the application deserializes user-controlled data, during code review of serialization/deserialization logic, and when testing applications using Java RMI, PHP unserialize, Python pickle, .NET BinaryFormatter, or Ruby Marshal.

## Prerequisites

- Java Runtime for ysoserial gadget chain generation
- PHP environment for PHPGGC gadget generation
- Python 3.10+ with pickle, PyYAML for Python deserialization testing
- Burp Suite with Java Deserialization Scanner plugin
- Python pickle, YAML, JSON deserialization knowledge
- .NET deserialization tools (ysoserial.net)
- Understanding of common gadget libraries (CommonsCollections, Spring, Fastjson)

## Workflow

1. Identify serialized data: Search for base64-encoded, hex-encoded, or binary serialized objects in requests, cookies, hidden fields, and API requests
2. Detect deserialization endpoints: Send malformed serialized objects and observe error messages, stack traces, or time delays
3. Fingerprint serialization format: Identify the format (Java Serialization magic bytes `aced0005`, PHP serialization `O:`, Python pickle `(dp0`, .NET BinaryFormatter, JSON/XML serialization)
4. Enumerate libraries: Analyze stack traces, error messages, and application fingerprints to identify gadget library versions
5. Generate payloads with ysoserial: Use appropriate gadget chain for identified libraries (CommonsCollections, Spring, Jackson, Fastjson, Hibernate)
6. Test blind deserialization: Use out-of-band (OOB) payloads with DNS callback to confirm code execution
7. Exploit for RCE: Generate payloads that execute commands, write webshells, or establish reverse shell connections
8. Document all entry points: Record cookie names, parameters, and endpoints that accept serialized data
9. Test for memory corruption: For C/C++ deserialization, test with malformed inputs for buffer overflow conditions
10. Report with proof of concept: Include exact payload, entry point, gadget chain used, and command output

## Verification

- Deserialization endpoint is confirmed with OOB callback or error-based detection
- Gadget chain is valid for the specific library version on the target
- RCE payload executes `whoami`, `hostname`, or `id` and output is retrieved
- Multiple gadget chains are tested if the first fails (CommonsCollections, Spring, Fastjson)
- All identified serialized data entry points are documented with format and confidence level
- Payload survives encoding/decoding layers (base64, URL encoding, hex) used by the application
