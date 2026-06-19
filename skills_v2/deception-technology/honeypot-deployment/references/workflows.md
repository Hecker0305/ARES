# Cowrie Honeypot Configuration
```python
# cowrie.cfg
[honeypot]
hostname = web-prod-01
listen_port = 2222

[database_host]
host = localhost
port = 3306
database = cowrie

[output_siem]
url = tcp://siem.local:10514
format = json

[output_malware]
enabled = true
download_dir = /opt/cowrie/var/lib/cowrie/downloads
```

# Dionaea Service Configuration
```python
# dionaea.conf
[modules]
modules = python/pyev.py,python/logsql.py,python/logxml.py
listen = 0.0.0.0
listen_port_map = 21/tcp, 80/tcp, 135/tcp, 443/tcp, 445/tcp, 1433/tcp, 3306/tcp
```
