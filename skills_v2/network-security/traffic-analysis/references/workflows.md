# Deep Technical Procedures

## PCAP Analysis with Zeek

```bash
# Run Zeek on PCAP file
zeek -r capture.pcap local "Log::default_rotation_interval = 1 day"

# Generated logs:
# conn.log - All connections
# dns.log - DNS queries  
# http.log - HTTP requests
# ssl.log - TLS certificates
# files.log - Extracted files

# Analyze conn.log for beacons
cat conn.log | zeek-cut ts id.orig_h id.resp_h proto service duration orig_bytes | \
  awk '$6 > 0 && $6 < 100 {print $2, $3, $1}' | sort | uniq -c | sort -rn | head -20
```

## C2 Beacon Detection in Python

```python
import pandas as pd
import numpy as np

def detect_beacons(conn_log):
    df = pd.read_csv(conn_log, sep='\t', comment='#')
    
    # Group by source-destination pair
    pairs = df.groupby(['id.orig_h', 'id.resp_h', 'id.resp_p'])
    
    beacons = []
    for (src, dst, port), group in pairs:
        if len(group) < 10:
            continue
        
        times = group['ts'].values
        intervals = np.diff(times)
        
        if len(intervals) < 5:
            continue
        
        std = np.std(intervals)
        mean = np.mean(intervals)
        cv = std / mean if mean > 0 else 0
        
        if cv < 0.3 and mean > 1:  # Low variation in intervals
            sizes = group[['orig_bytes', 'resp_bytes']].dropna().values
            size_std = np.std([s[0] for s in sizes]) if len(sizes) > 0 else 0
            
            beacons.append({
                'source': src,
                'destination': dst,
                'port': port,
                'connections': len(group),
                'mean_interval': round(mean, 2),
                'std_interval': round(std, 2),
                'cv': round(cv, 3),
                'size_std': round(size_std, 2)
            })
    
    return pd.DataFrame(beacons).sort_values('cv')
```

## NetFlow Analysis

```bash
# nfdump analysis
nfdump -R /data/nfcapd/ -s ip/flows -n 20  # Top talkers
nfdump -R /data/nfcapd/ -c 'proto tcp and port 443'  # Filter HTTPS
nfdump -R /data/nfcapd/ -c 'dst net 10.0.0.0/8'  # Internal destination

# Export to CSV
nfdump -R /data/nfcapd/ -o csv -c 'not src net 10.0.0.0/8' > external_traffic.csv
```

## TLS Certificate Analysis

```python
def analyze_tls_certs(ssl_log):
    df = pd.read_csv(ssl_log, sep='\t', comment='#')
    
    # Self-signed certificate detection
    self_signed = df[df['validation_status'] == 'self-signed']
    
    # Unusual SNI patterns
    suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click']
    suspicious = df[df['server_name'].str.endswith(tuple(suspicious_tlds), na=False)]
    
    return {'self_signed': len(self_signed), 'suspicious_sni': len(suspicious)}
```
