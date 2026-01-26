#!/bin/bash
# create_visible_alert.sh

# Créer une alerte dans le format EXACT de Kibana 7.x
ALERT_DATA=$(cat << 'EOF'
{
  "@timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
  "event": {
    "action": "alert",
    "category": ["intrusion_detection"],
    "created": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
    "dataset": "alert",
    "kind": "alert",
    "module": "siem",
    "type": ["denied"]
  },
  "signal": {
    "status": "open",
    "rule": {
      "author": ["Elastic"],
      "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
      "description": "SSH brute force attack detected",
      "enabled": true,
      "false_positives": [],
      "from": "now-360s",
      "id": "fec77f36-da19-11f0-a87b-cb58da5dfbba",
      "immutable": false,
      "index": ["auditbeat-*", "filebeat-*", "packetbeat-*", "winlogbeat-*"],
      "interval": "5m",
      "language": "kuery",
      "max_signals": 100,
      "name": "SSH Bruteforce Attack Detected",
      "query": "event.action:\"user_login\" and event.outcome:\"failure\"",
      "references": [],
      "risk_score": 21,
      "risk_score_mapping": [],
      "rule_id": "ssh-bruteforce-detection",
      "severity": "low",
      "severity_mapping": [],
      "tags": ["SSH", "Bruteforce", "Authentication"],
      "throttle": "no_actions",
      "to": "now",
      "type": "query",
      "updated_at": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
      "version": 1
    },
    "original_time": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
    "original_event": {
      "action": "user_login",
      "dataset": "auditd.log",
      "module": "auditd"
    },
    "ancestors": [
      {
        "id": "$(uuidgen)",
        "type": "event",
        "index": "auditbeat-*",
        "depth": 0
      }
    ],
    "status": "open"
  },
  "host": {
    "name": "server-01",
    "ip": "192.168.1.100"
  },
  "source": {
    "ip": "10.0.0.1",
    "port": 54321
  },
  "destination": {
    "ip": "192.168.1.100",
    "port": 22
  },
  "user": {
    "name": "root"
  },
  "message": "SSH login failed - possible brute force attack",
  "tags": ["ssh", "bruteforce", "security"]
}
EOF
)

# Remplacer les variables dans le JSON
ALERT_DATA=$(echo "$ALERT_DATA" | envsubst)

# Envoyer l'alerte
curl -u "elastic:changeme123" -X POST \
  "http://localhost:9200/.siem-signals-default-000001/_doc" \
  -H "Content-Type: application/json" \
  -d "$ALERT_DATA"

echo ""
echo "✅ Alerte créée dans .siem-signals-default-000001"
echo "🔗 Accédez à: http://localhost:5601/app/security/alerts"