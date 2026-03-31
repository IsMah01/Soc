#!/usr/bin/env python3

import requests
import json
import time
from datetime import datetime

ELASTIC_HOST = "http://localhost:9200"
USER = "elastic"
PASSWORD = "changeme123"

INDEX = "logs-security-test"

def send_log():
    log = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "event": {
            "category": "authentication",
            "type": "start",
            "action": "login_attempt"
        },
        "user": {
            "name": "attacker"
        },
        "host": {
            "name": "server-01"
        },
        "source": {
            "ip": "192.168.1.200"
        },
        "message": "Failed SSH login attempt"
    }

    r = requests.post(
        f"{ELASTIC_HOST}/{INDEX}/_doc",
        auth=(USER, PASSWORD),
        headers={"Content-Type": "application/json"},
        json=log
    )

    if r.status_code in [200, 201]:
        print("✅ Log envoyé :", r.json()["_id"])
    else:
        print("❌ Erreur :", r.text)

def main():
    print("🚀 Génération de logs pour déclencher la règle Kibana")

    for i in range(5):
        send_log()
        time.sleep(2)

if __name__ == "__main__":
    main()
