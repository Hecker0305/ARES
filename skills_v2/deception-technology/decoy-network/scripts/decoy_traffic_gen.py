#!/usr/bin/env python3
"""Generate realistic decoy network traffic."""
import random
import time
from datetime import datetime
from scapy.all import IP, TCP, UDP, Ether, sendp
from scapy.layers.http import HTTP, HTTPRequest
import requests

class DecoyTrafficGenerator:
    def __init__(self, interface: str = "eth0",
                 gateway: str = "192.168.100.1",
                 dns_server: str = "192.168.100.10"):
        self.iface = interface
        self.gateway = gateway
        self.dns = dns_server
        self.users = ["jdoe", "asmith", "bwilson", "kchen", "mlee"]
        self.servers = ["web-01", "app-01", "db-01", "fs-01", "mail-01"]
        self.base_ip = "192.168.100"

    def generate_user_activity(self, user: str, ip: str):
        """Simulate a user performing daily work activities."""
        activities = [
            self.http_browse,
            self.dns_query,
            self.ldap_auth,
            self.smb_file_access
        ]
        for _ in range(random.randint(5, 15)):
            activity = random.choice(activities)
            try:
                activity(ip)
            except:
                pass
            time.sleep(random.uniform(2, 30))

    def http_browse(self, src_ip: str):
        targets = ["https://web-01.internal/reports",
                   "https://web-01.internal/dashboard",
                   "https://www.example.com",
                   "https://mail.internal/owa"]
        target = random.choice(targets)
        try:
            requests.get(target, timeout=5, proxies={})
        except:
            pass

    def dns_query(self, src_ip: str):
        from scapy.all import IP, UDP, DNS, DNSQR, send
        dst = self.dns
        domains = ["internal.company.com", "mail.company.com",
                   "sharepoint.company.com", "vpn.company.com"]
        query = random.choice(domains)
        pkt = IP(src=src_ip, dst=dst) / UDP(sport=random.randint(1024, 65535), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=query))
        send(pkt, iface=self.iface, verbose=0)

    def ldap_auth(self, src_ip: str):
        # Simulate LDAP auth traffic to domain controller
        pkt = IP(src=src_ip, dst=f"{self.base_ip}.10") / \
              UDP(sport=random.randint(1024, 65535), dport=389)
        send(pkt, iface=self.iface, verbose=0)

    def smb_file_access(self, src_ip: str):
        pkt = IP(src=src_ip, dst=f"{self.base_ip}.20") / \
              TCP(sport=random.randint(1024, 65535), dport=445, flags="S")
        send(pkt, iface=self.iface, verbose=0)

    def start_simulation(self, duration_minutes: int = 60):
        end_time = time.time() + (duration_minutes * 60)
        while time.time() < end_time:
            user = random.choice(self.users)
            ip = f"{self.base_ip}.{random.randint(50, 100)}"
            self.generate_user_activity(user, ip)
            print(f"[{datetime.now().isoformat()}] Simulated {user}@{ip}")
            time.sleep(random.uniform(30, 120))

if __name__ == "__main__":
    gen = DecoyTrafficGenerator()
    gen.start_simulation(duration_minutes=10)
