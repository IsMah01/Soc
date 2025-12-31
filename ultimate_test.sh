#!/bin/bash
echo "=== TEST ULTIME SYNCHRONISATION ==="
echo "Heure: $(date)"
echo

# 1. Supprimer l'état précédent pour repartir à zéro
echo "1. 🔄 Réinitialisation état..."
docker-compose exec elastic-thehive-sync rm -f /data/sync_state.json
docker-compose restart elastic-thehive-sync
sleep 10

# 2. Vérifier état
echo -e "\n2. 📊 État service:"
docker-compose ps elastic-thehive-sync

# 3. Créer alerte TEST FRAÎCHE
echo -e "\n3. 🚨 Création alerte fraîche..."
ALERT_ID="fresh-test-$(date +%s)"
curl -s -u elastic:<REMOVED_DEFAULT_PASSWORD> -X POST "http://localhost:9200/.siem-signals-default-000001/_doc" \
  -H 'Content-Type: application/json' \
  -d '{
    "@timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")'",
    "signal": {
      "rule": {
        "id": "'"$ALERT_ID"'",
        "name": "[FRESH TEST] Synchronisation corrigée",
        "description": "Test avec fingerprint unique pour éviter les conflits",
        "severity": 3
      }
    },
    "host": {"name": "test-server-01"},
    "event": {"category": "intrusion", "action": "detected"}
  }' | jq -r '"   ID Elastic: \(._id)"'

# 4. Attendre et surveiller
echo -e "\n4. ⏳ Surveillance logs (40s)..."
for i in {1..8}; do
    sleep 5
    echo -n "."
done
echo

# 5. Vérifier logs
echo -e "\n5. 📋 Logs récentes:"
docker-compose logs --tail=15 elastic-thehive-sync | grep -E "(Nouvelle|✓|✗|Cycle)"

# 6. Chercher l'alerte dans TheHive
echo -e "\n6. 🔍 Recherche dans TheHive:"
curl -s "http://localhost:9000/api/alert" \
  -H "Authorization: Bearer iWtYr7XOrugw5HqUKg4HvXizcL7CV+qD" | \
  jq -r '.[] | select(.title | contains("FRESH TEST")) | "   ✅ TROUVÉE: \(.title)\n      ID: \(.id)\n      Date: \(.date | todate)\n      SourceRef: \(.sourceRef)"'

# 7. Vérifier état
echo -e "\n7. 💾 État sauvegardé:"
docker-compose exec elastic-thehive-sync cat /data/sync_state.json 2>/dev/null | \
  jq -r '"   Alertes traitées: \(.total_processed)\n   Dernière maj: \(.updated)"' 2>/dev/null

echo -e "\n✅ Test ultime terminé"
