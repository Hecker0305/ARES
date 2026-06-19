# Deep Technical Procedures

## Rule Analysis with Python

```python
import pandas as pd
import ipaddress
from typing import List, Dict

class FirewallRuleAnalyzer:
    def __init__(self, rules_df: pd.DataFrame):
        self.rules = rules_df
        self.findings = []
        
    def find_shadowed_rules(self):
        """Detect rules that will never be matched"""
        for i, rule1 in self.rules.iterrows():
            for j, rule2 in self.rules.iterrows():
                if i >= j:
                    continue
                if (self._is_subnet(rule1['src'], rule2['src']) and
                    self._is_subnet(rule1['dst'], rule2['dst']) and
                    self._service_match(rule1['service'], rule2['service'])):
                    self.findings.append({
                        'type': 'shadowed',
                        'shadowed_rule': i + 1,
                        'shadowing_rule': j + 1,
                        'severity': 'HIGH'
                    })
                    
    def _is_subnet(self, cidr1, cidr2):
        try:
            net1 = ipaddress.ip_network(cidr1, strict=False)
            net2 = ipaddress.ip_network(cidr2, strict=False)
            return net1.subnet_of(net2) and net1 != net2
        except:
            return False
            
    def _service_match(self, svc1, svc2):
        if svc1 == 'any' or svc2 == 'any':
            return True
        return svc1 == svc2

    def find_redundant_rules(self):
        dupes = self.rules.duplicated(subset=['src', 'dst', 'service', 'action'], keep=False)
        for idx in self.rules[dupes].index:
            self.findings.append({
                'type': 'redundant',
                'rule_number': idx + 1,
                'severity': 'MEDIUM'
            })
```

## Cisco ASA Rule Audit

```bash
# Export ACL from ASA
show running-config | grep access-list > asa_acls.txt

# Check rule hit counts
show access-list | grep -E "\(hitcnt=[0-9]+\)" > asa_hits.txt

# Find rules with zero hits
grep "hitcnt=0" asa_hits.txt

# Find overly permissive rules
grep "any any" asa_acls.txt
```

## Palo Alto Rule Analysis

```python
from pan.xapi import PanXapi
import xml.etree.ElementTree as ET

def analyze_panorama_rules(panorama_ip, api_key):
    xapi = PanXapi(hostname=panorama_ip, api_key=api_key)
    
    # Get all security rules
    xapi.op(cmd='show rulebase security-rules')
    root = ET.fromstring(xapi.xml_result())
    
    rules = []
    for rule in root.findall('.//entry'):
        name = rule.get('name')
        source = rule.findtext('source/member', 'any')
        destination = rule.findtext('destination/member', 'any')
        service = rule.findtext('service/member', 'any')
        action = rule.findtext('action', 'allow')
        rules.append({'name': name, 'src': source, 'dst': destination, 'svc': service, 'action': action})
    
    return rules
```
