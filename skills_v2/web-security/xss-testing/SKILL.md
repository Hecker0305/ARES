---
name: xss-testing
description: >-
  Comprehensive cross-site scripting (XSS) testing methodology covering reflected, stored, DOM-based, and blind XSS.
  Includes context-aware payload crafting, WAF evasion, and exploitation for session hijacking and data theft.
domain: web-security
subdomain: xss-testing
tags: [xss, cross-site-scripting, web-security, client-side, owasp-top-10, injection]
mitre_attack: [T1059, T1189, T1204, T1552, T1608]
nist_csf: [PR.AC-4, PR.DS-2, DE.CM-4, DE.CM-8]
d3fend: [D3-WAF, D3-CSP, D3-XSS, D3-SAN]
nist_ai_rmf: [DETECT-2.1, MEASURE-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during web application assessments, user input validation testing, content security policy (CSP) evaluations, and when testing for XSS vulnerabilities in both legacy and modern SPA applications.

## Prerequisites

- Burp Suite or OWASP ZAP with XSS scanner
- Browser with developer tools and XSS-me browser extension
- Knowledge of JavaScript, HTML, DOM manipulation
- Python 3.10+ with requests and selenium for automated testing
- Understanding of CSP headers and bypass techniques
- Polyglot payload generation tools (XSStrike, BruteXSS)

## Workflow

1. Identify injection contexts: Analyze where user input appears (HTML element, attribute, script block, event handler, CSS, URL)
2. Test reflected XSS: Submit payload in URL/parameter and observe response without encoding
3. Test stored XSS: Submit payload through forms, comments, profile fields, and review persistent storage
4. Test DOM-based XSS: Analyze JavaScript source to identify sink functions (innerHTML, document.write, eval, setTimeout)
5. Craft context-specific payloads: Adapt payloads based on the injection context (HTML entity, JS string, CSS URL)
6. Bypass filters: Test case variation, event handler abuse, encoding bypass, template literal injection
7. Test CSP headers: Evaluate CSP policy strength and identify bypasses (JSONP, CDN abuse, base-uri injection)
8. Detect blind XSS: Use callback URLs (XSS Hunter, Burp Collaborator) to detect XSS in admin panels or logs
9. Exploit for impact: Demonstrate session hijacking, keylogging, CSRF token theft, or internal network scanning
10. Document XSS findings: Include injection point, confirmed context, payload, CSP state, and impact demonstration

## Verification

- Confirmed XSS with at least one working payload in each distinct context
- CSP policy is documented and bypass tested for all script execution paths
- Blind XSS is verified with out-of-band callback from target system
- Payload executes in the context of the target user without user interaction
- Impact demonstration (alert(document.cookie) or image request to attacker server) is functional
- WAF bypass payloads are documented if WAF is present and blocking standard payloads
