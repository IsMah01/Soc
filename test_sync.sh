#!/bin/bash
echo "=== TEST SYNCHRONISATION ==="
echo "Heure: $(date)"
echo

# 1. État du service
echo "1. 📦 Service:"
docker-compose ps elastic-thehive-sync

# 2. Logs récentes
echo -e "\n2. 📋 Logs:"
docker-compose logs --tail=5 elastic-thehive-sync

# 3. Créer une alerte de test
echo -e "\n3. 🚨 Création alerte test..."
TEST_ID="sync-test-$(date +%s)"
curl -s -u elastic:<REMOVED_DEFAULT_PASSWORD> -X POST "http://localhost:9200/.siem-signals-default-000001/_doc" \
  -H 'Content-Type: application/json' \
  -d '{
    "@timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")'",
    "signal": {
      "rule": {
        "id": "'"$TEST_ID"'",
        "name": "[TEST SYNC] Vérification synchronisation",
        "description": "Test automatique de la synchronisation Elastic → TheHive",
        "severity": 2
      }
    },
    "host": {"name": "test-sync"},
    "event": {"category": "test"}
  }' | jq -r '"   ID Elastic: \(._id)"'

# 4. Attendre synchronisation
echo -e "\n4. ⏳ Attente synchronisation (35s)..."
sleep 35

# 5. Vérifier dans TheHive
echo -e "\n5. 📊 Vérification TheHive:"
curl -s "http://localhost:9000/api/alert?range=last5m" \
  -H "Authorization: Bearer iWtYr7XOrugw5HqUKg4HvXizcL7CV+qD" | \
  jq -r 'length as $count | "   Alertes dernières 5min: \($count)"'

echo -e "\n✅ Test terminé"
