#!/usr/bin/env python3
"""
THREXIS Telemetry Collector Agent
Engineered for Ubuntu / Debian / RHEL Linux environments.
Real-time live monitoring of SSH authentication and system security logs.
Supports both systemd journalctl (Ubuntu 24.04/22.04+) and file-based log tailing (/var/log/auth.log).
Uses standard library exclusively (urllib, json, re, socket, os, subprocess, threading).
"""

import os
import re
import sys
import time
import json
import socket
import select
import threading
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

CONFIG_FILE = Path(__file__).resolve().parent / "config.json"
STATE_FILE = Path(__file__).resolve().parent / ".collector_state.json"

# Comprehensive regex patterns matching OpenSSH, PAM, and Sudo failure/success variants
PATTERNS = [
    # 1. Standard SSH password failure (valid or invalid user)
    (
        re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"),
        "ssh_auth_failure"
    ),
    # 2. Invalid user attempt
    (
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"),
        "ssh_auth_failure"
    ),
    # 3. PAM authentication failure
    (
        re.compile(r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>[\d\.:a-fA-F]+)(?:\s+user=(?P<user>\S+))?"),
        "ssh_auth_failure"
    ),
    # 4. Connection closed/reset during preauth (often automated brute-force disconnect)
    (
        re.compile(r"(?:Disconnected from|Connection (?:closed|reset) by) authenticating user (?P<user>\S+) (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"),
        "ssh_auth_failure"
    ),
    # 5. Successful login
    (
        re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"),
        "ssh_auth_success"
    ),
    # 6. Sudo command or failure
    (
        re.compile(r"sudo:\s+(?P<user>\S+)\s+:\s+(?P<message>.*)"),
        "sudo_event"
    )
]

class ThrexisCollector:
    def __init__(self, config_path: Path):
        self.config = self.load_config(config_path)
        self.state = self.load_state()
        self.api_url = self.config.get("api_url", "http://192.168.56.1:8000/api/v1").rstrip("/")
        self.api_key = self.config.get("api_key", "threxis-collector-secret-2026")
        self.host_id = self.config.get("host_id", f"ubuntu-{socket.gethostname()}")
        self.hostname = self.config.get("hostname", socket.gethostname())
        self.events_transmitted = self.state.get("events_transmitted", 0)
        self.pending_events = []
        self.lock = threading.Lock()
        self.last_heartbeat_time = 0.0
        self.running = True

    def load_config(self, path: Path) -> dict:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def load_state(self) -> dict:
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"offsets": {}, "events_transmitted": 0}

    def save_state(self):
        with self.lock:
            self.state["events_transmitted"] = self.events_transmitted
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)

    def parse_log_line(self, line: str, source_tag: str):
        line_clean = line.strip()
        if not line_clean:
            return None

        event_type = None
        user = None
        source_ip = None
        source_port = None
        message = line_clean

        for regex, ev_type in PATTERNS:
            m = regex.search(line_clean)
            if m:
                event_type = ev_type
                gd = m.groupdict()
                user = gd.get("user")
                source_ip = gd.get("ip")
                if "port" in gd and gd["port"]:
                    try:
                        source_port = int(gd["port"])
                    except ValueError:
                        pass
                if event_type == "ssh_auth_failure":
                    message = f"SSH authentication failure for user '{user or 'unknown'}' from {source_ip or 'unknown IP'}"
                elif event_type == "ssh_auth_success":
                    message = f"SSH login succeeded for user '{user}' from {source_ip}"
                elif event_type == "sudo_event":
                    msg_detail = gd.get("message", "")
                    message = f"Sudo invocation by '{user}': {msg_detail}"
                break

        if not event_type:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        return {
            "host": self.hostname,
            "timestamp": now_iso,
            "source": source_tag,
            "event_type": event_type,
            "user": user,
            "source_ip": source_ip,
            "source_port": source_port,
            "message": message,
            "raw_log": line_clean
        }

    def queue_event(self, evt: dict):
        with self.lock:
            self.pending_events.append(evt)
            print(f"[+] Live Event Captured: [{evt['event_type']}] user={evt['user']} ip={evt['source_ip']} -> Queue: {len(self.pending_events)}")

    def send_heartbeat(self):
        url = f"{self.api_url}/collector/heartbeat"
        
        # Determine local IP
        local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                pass

        payload = {
            "host_id": self.host_id,
            "hostname": self.hostname,
            "ip_address": local_ip,
            "collector_version": "1.0.0",
            "os_info": f"Linux {os.uname().release if hasattr(os, 'uname') else 'Ubuntu'} ({socket.gethostname()})",
            "events_transmitted": self.events_transmitted
        }
        headers = {
            "Content-Type": "application/json",
            "X-Collector-Key": self.api_key
        }
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    self.last_heartbeat_time = time.time()
                    print(f"[*] Heartbeat acknowledged by THREXIS API ({local_ip} -> {self.api_url})")
        except Exception as e:
            print(f"[!] Warning: Cannot reach THREXIS API at {self.api_url}: {e}", file=sys.stderr)

    def flush_batch(self):
        with self.lock:
            if not self.pending_events:
                return
            batch_to_send = list(self.pending_events)

        url = f"{self.api_url}/telemetry/ingest"
        payload = {
            "collector_id": self.host_id,
            "events": batch_to_send,
            "batch_timestamp": datetime.now(timezone.utc).isoformat()
        }
        headers = {
            "Content-Type": "application/json",
            "X-Collector-Key": self.api_key
        }
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    sent_count = len(batch_to_send)
                    with self.lock:
                        # Remove sent items
                        self.pending_events = self.pending_events[sent_count:]
                        self.events_transmitted += sent_count
                    self.save_state()
                    print(f"[✓] Transmitted {sent_count} live security events to THREXIS. Total streamed: {self.events_transmitted}")
        except Exception as e:
            print(f"[!] Notice: Ingestion endpoint offline or unreachable ({e}). Buffered {len(batch_to_send)} events.", file=sys.stderr)

    def start_journalctl_stream(self):
        """
        Continuously streams real-time SSH events directly from systemd-journald.
        Essential for Ubuntu 24.04 and systems without rsyslog.
        """
        cmd = ["journalctl", "-u", "ssh", "-u", "sshd", "-f", "-n", "0", "-o", "cat"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            print("[*] Active systemd journal stream attached: monitoring 'ssh' and 'sshd' units.")
            for line in proc.stdout:
                if not self.running:
                    break
                evt = self.parse_log_line(line, "journald:ssh")
                if evt:
                    self.queue_event(evt)
                    self.flush_batch()
        except FileNotFoundError:
            print("[!] journalctl not found; operating exclusively in file-tailing mode.", file=sys.stderr)
        except Exception as e:
            print(f"[!] Journalctl streaming notice: {e}", file=sys.stderr)

    def poll_file_sources(self):
        """
        Polls configured file sources (/var/log/auth.log, /var/log/secure, /var/log/syslog).
        """
        for src in self.config.get("sources", []):
            path_str = src.get("path")
            key = src.get("key", Path(path_str).name)
            if not path_str or not os.path.exists(path_str):
                continue

            last_offset = self.state["offsets"].get(key, 0)
            try:
                file_size = os.path.getsize(path_str)
            except OSError:
                continue

            # Log rotation detection
            if file_size < last_offset:
                print(f"[*] Log rotation detected for {path_str}. Resetting offset.")
                last_offset = 0

            if file_size > last_offset:
                try:
                    with open(path_str, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(last_offset)
                        for line in f:
                            evt = self.parse_log_line(line, key)
                            if evt:
                                self.queue_event(evt)
                        self.state["offsets"][key] = f.tell()
                except Exception as e:
                    print(f"[!] Error reading {path_str}: {e}", file=sys.stderr)

    def run(self):
        print("==================================================")
        print(" THREXIS Real-Time Telemetry Collector Agent")
        print(f" Host: {self.hostname} ({self.host_id})")
        print(f" Target API: {self.api_url}")
        print("==================================================")
        
        self.send_heartbeat()

        # Start journald tailing in background thread
        journal_thread = threading.Thread(target=self.start_journalctl_stream, daemon=True)
        journal_thread.start()

        while self.running:
            try:
                # Poll files (for auth.log / syslog)
                self.poll_file_sources()

                # Flush any buffered events immediately
                if self.pending_events:
                    self.flush_batch()

                # Periodic heartbeat
                now = time.time()
                if now - self.last_heartbeat_time >= self.config.get("heartbeat_interval_sec", 10):
                    self.send_heartbeat()

                time.sleep(1.0)
            except KeyboardInterrupt:
                print("\n[*] Stopping collector agent gracefully...")
                self.running = False
                self.flush_batch()
                self.save_state()
                break
            except Exception as e:
                print(f"[!] Collector main loop exception: {e}", file=sys.stderr)
                time.sleep(2.0)

if __name__ == "__main__":
    collector = ThrexisCollector(CONFIG_FILE)
    collector.run()
