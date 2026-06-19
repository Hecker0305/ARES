# Deep Technical Procedures

## Hypothesis Formulation Template
```python
hunt_template = {
    "hypothesis_id": "HT-2024-001",
    "adversary": "UNC2452",
    "technique": "T1190 - Exploit Public-Facing Application",
    "behavior": "HTTP POST to /ews/exchange.asmx with Content-Type application/xml",
    "data_source": "IIS/Frontend logs",
    "query": "index=proxy src_ip!=10.0.0.0/8 method=POST uri=/ews/exchange.asmx useragent=*",
    "expected_fp_rate": "0.05",
    "time_range": "-30d",
    "priority": "HIGH"
}
```

## Splunk SPL Examples

### Hunt for PowerShell Remoting (T1059.001)
```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
| search ScriptBlockText=*Invoke-Command* OR ScriptBlockText=*New-PSSession* OR ScriptBlockText=*Enter-PSSession*
| eval cmd_length = len(ScriptBlockText)
| where cmd_length > 500
| table _time, host, UserID, ScriptBlockText, cmd_length
| sort -_time
```

### Hunt for LSASS Access (T1003.001)
```spl
index=windows EventCode=4663 ObjectName=*lsass.exe
| search AccessMask=0x705 OR AccessMask=0x10
| table _time, host, SubjectUserName, ProcessName, AccessMask, ObjectName
| eval suspicious = if(ProcessName!=C:\\Windows\\System32\\lsass.exe AND ProcessName!=C:\\Windows\\system32\\svchost.exe, "YES", "NO")
| where suspicious="YES"
```

### Hunt for DNS Tunneling
```spl
index=network dest_port=53
| eval query_length = len(query)
| where query_length > 52
| stats count by src_ip, query, query_length
| where count > 100
| sort - count
```

## Python Hunting Framework

```python
import pandas as pd
import numpy as np

class HypothesisHunt:
    def __init__(self, hypothesis, log_source):
        self.hypothesis = hypothesis
        self.log_source = log_source
        self.results = pd.DataFrame()
        self.baselines = {}

    def establish_baseline(self, data):
        """Build statistical baseline from historical data"""
        self.baselines['mean'] = data.mean()
        self.baselines['std'] = data.std()
        self.baselines['p95'] = data.quantile(0.95)

    def detect_anomaly(self, observation):
        """Z-score based anomaly detection"""
        if observation > self.baselines['mean'] + 3 * self.baselines['std']:
            return 'CRITICAL'
        elif observation > self.baselines['p95']:
            return 'SUSPICIOUS'
        return 'NORMAL'

    def run_hunt(self, data):
        """Execute the hunt hypothesis against provided data"""
        self.establish_baseline(data['historical'])
        data['current']['risk_score'] = data['current'].apply(
            lambda x: self.detect_anomaly(x), axis=1
        )
        return data['current'][data['current']['risk_score'] != 'NORMAL']
```
