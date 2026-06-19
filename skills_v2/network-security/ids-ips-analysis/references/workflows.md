# Deep Technical Procedures

## Snort Custom Rule Examples

### C2 Beacon Detection
```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET C2 Beacon Detected - Periodic HTTP Check-in";
  flow:to_server,established;
  content:"|0d 0a|User-Agent|3a 20|Mozilla/5.0"; 
  pcre:"/(GET|POST)\s+\/[a-z0-9]{10,20}\.php\s+HTTP/";
  threshold:type both, track by_src, count 5, seconds 60;
  sid:1000001; rev:1; priority:1;
  reference:url,attack.mitre.org/techniques/T1071;
  classtype:trojan-activity;)
```

### DNS Tunneling Detection
```
alert udp $HOME_NET any -> any 53 (
  msg:"ET DNS Tunneling - Long Subdomain Query";
  content:"|01 00 00 01 00 00 00 00 00 00|";
  dsize:>150;
  byte_test:1,!&,0x08,1;
  pcre:"/(?:[a-z0-9]{30,}\.){2,}[a-z]{2,6}/";
  sid:1000002; rev:1; priority:1;
  classtype:policy-violation;)
```

## Suricata Rule Performance Tuning

```yaml
# suricata.yaml tuning for performance
vars:
  address-groups:
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080,443,8443"

rule-reload: true
detect:
  profile: medium
  custom-rules:
    - /etc/suricata/rules/local.rules

flow:
  memcap: 512mb
  hash-size: 65536

defrag:
  memcap: 256mb

app-layer:
  protocols:
    http:
      enabled: yes
      memcap: 256mb
```

## Alert Analysis with Python

```python
import pandas as pd
from collections import Counter

def analyze_ids_alerts(log_file, top_n=10):
    df = pd.read_csv(log_file, sep='\t')
    
    top_sigs = df['signature'].value_counts().head(top_n)
    top_src = df['src_ip'].value_counts().head(top_n)
    top_dst = df['dest_ip'].value_counts().head(top_n)
    
    # False positive candidates (high volume, same src/dst)
    fp_candidates = df.groupby(['signature', 'src_ip', 'dest_ip']).size()
    fp_candidates = fp_candidates[fp_candidates > 100].sort_values(ascending=False)
    
    return {
        'top_signatures': top_sigs.to_dict(),
        'top_sources': top_src.to_dict(),
        'top_destinations': top_dst.to_dict(),
        'fp_candidates': fp_candidates.head(20).to_dict()
    }
```
