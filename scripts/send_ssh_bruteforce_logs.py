#!/usr/bin/env python3
import os
from datetime import datetime, timezone

import requests


ELASTIC_HOST = os.getenv("ELASTIC_HOST", "http://localhost:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "<REMOVED_DEFAULT_PASSWORD>")
INDEX = os.getenv("SSH_LOG_INDEX", "logs-ssh-auth-test")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_event(i):
    return {
        "@timestamp": utc_now(),
        "event": {
            "category": "authentication",
            "type": ["start"],
            "action": "ssh_login_failed",
            "outcome": "failure",
            "dataset": "system.auth",
            "provider": "sshd",
        },
        "process": {
            "name": "sshd",
        },
        "system": {
            "auth": {
                "ssh": {
                    "event": "Failed password",
                    "method": "password",
                }
            }
        },
        "source": {
            "ip": "203.0.113.45",
            "port": 42000 + i,
            "geo": {
                "country_name": "Test-Country",
                "city_name": "Test-City",
            },
        },
        "client": {
            "ip": "203.0.113.45",
        },
        "destination": {
            "ip": "10.10.20.15",
            "port": 22,
        },
        "related": {
            "ip": ["203.0.113.45", "10.10.20.15"],
        },
        "host": {
            "name": "srv-linux-ssh-01",
            "ip": ["10.10.20.15"],
        },
        "user": {
            "name": f"admin{i}",
            "email": f"admin{i}@lab.local",
        },
        "user_agent": {
            "original": "OpenSSH brute-force test client",
        },
        "message": f"Failed password for admin{i} from 203.0.113.45 port {42000 + i} ssh2",
        "tags": ["ssh", "brute-force", "authentication", "test"],
    }


def main():
    events = [build_event(i) for i in range(1, 7)]
    bulk_lines = []
    for event in events:
        bulk_lines.append({"create": {"_index": INDEX}})
        bulk_lines.append(event)

    payload = "\n".join(__import__("json").dumps(line) for line in bulk_lines) + "\n"
    response = requests.post(
        f"{ELASTIC_HOST}/_bulk",
        auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data=payload,
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()
    if data.get("errors"):
        raise SystemExit(f"Bulk indexing returned errors: {data}")

    requests.post(
        f"{ELASTIC_HOST}/{INDEX}/_refresh",
        auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        timeout=10,
    ).raise_for_status()

    print(f"Indexed {len(events)} SSH failed authentication events into {INDEX}")
    print("source.ip=203.0.113.45 destination.ip=10.10.20.15 host.name=srv-linux-ssh-01")


if __name__ == "__main__":
    main()
