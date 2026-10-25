#!/usr/bin/env python3
"""
THREXIS Telemetry Simulator & Live Demonstration Runner
Used for testing end-to-end telemetry ingestion, real-time alert triggering,
and classroom presentations.
"""

import sys
import time
import json
import uuid
import socket
import urllib.request
from datetime import datetime, timezone

API_BASE = "http://127.0.0.1:8000/api/v1"
COLLECTOR_KEY = "threxis-collector-secret-2026"

def send_heartbeat(host="ubuntu-vbox-demo", ip="192.168.56.101"):
    url = f"{API_BASE}/collector/heartbeat"
    payload = {
        "host_id": host,
        "hostname": host,
        "ip_address": ip,
        "collector_version": "1.0.0",
        "os_info": "Linux Ubuntu 24.04 LTS (Oracle VirtualBox VM)",
        "events_transmitted": 12
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Collector-Key": COLLECTOR_KEY},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        print(f"[*] Heartbeat sent: HTTP {resp.status}")

def simulate_ssh_attack(count=4, target_user="admin", attacker_ip="192.168.56.105", delay=1.0):
    print(f"\n[*] Generating controlled SSH authentication failure sequence ({count} events)...")
    url = f"{API_BASE}/telemetry/ingest"
    
    events = []
    now = datetime.now(timezone.utc)
    for i in range(count):
        evt_id = f"EVT-DEMO-{uuid.uuid4().hex[:8].upper()}"
        port = 45000 + i
        raw = f"Feb 26 14:22:{10 + i:02d} ubuntu-vbox sshd[{1042 + i}]: Failed password for {target_user} from {attacker_ip} port {port} ssh2"
        events.append({
            "event_id": evt_id,
            "host": "ubuntu-vbox-demo",
            "timestamp": now.isoformat(),
            "source": "auth.log",
            "event_type": "ssh_auth_failure",
            "user": target_user,
            "source_ip": attacker_ip,
            "source_port": port,
            "message": f"Failed password for {target_user} from {attacker_ip} port {port} ssh2",
            "raw_log": raw
        })

    payload = {
        "collector_id": "ubuntu-vbox-demo",
        "events": events,
        "batch_timestamp": now.isoformat()
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Collector-Key": COLLECTOR_KEY},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        print(f"[+] Ingestion Success: {res}")
        print(f"    Ingested: {res.get('ingested_count')} events")
        print(f"    Alerts Triggered: {res.get('alerts_triggered')}")

if __name__ == "__main__":
    print("==================================================")
    print(" THREXIS Demonstration Telemetry Generator")
    print("==================================================")
    send_heartbeat()
    time.sleep(1)
    simulate_ssh_attack(count=4, target_user="testuser", attacker_ip="192.168.56.105")
