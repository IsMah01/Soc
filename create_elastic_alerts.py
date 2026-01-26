#!/usr/bin/env python3
"""
Script SIMPLE pour créer des alertes visibles dans Kibana
"""

import json
import requests
import uuid
from datetime import datetime

ELASTIC_HOST = "http://localhost:9200"
USER = "elastic"
PASSWORD = "changeme123"

def create_and_send_alert():
    # Créer une alerte SIMPLE mais compatible
    alert = {
        "@timestamp": datetime.utcnow().isoformat()[:-3] + "Z",
        "event": {
            "kind": "alert",
            "category": "security",
            "type": "alert"
        },
        "signal": {
            "status": "open",
            "rule": {
                "name": "SSH Brute Force Detected",
                "description": "Multiple SSH authentication failures",
                "severity": "low",
                "risk_score": 21
            }
        },
        "host": {
            "name": "server-01"
        },
        "source": {
            "ip": "10.0.0.1"
        },
        "message": "SSH brute force attack detected",
        "tags": ["ssh", "security", "alert"]
    }
    
    # Essayer plusieurs indexes
    indexes = [
        "test-alerts-2025",
        "security-alerts",
        ".siem-signals-default-000001",
        ".alerts-security.alerts-default"
    ]
    
    for index in indexes:
        try:
            response = requests.post(
                f"{ELASTIC_HOST}/{index}/_doc",
                auth=(USER, PASSWORD),
                json=alert,
                timeout=10,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ Alerte créée dans: {index}")
                print(f"   ID: {response.json()['_id']}")
                return True
                
        except Exception as e:
            continue
    
    return False

def check_alert_in_kibana():
    """Vérifie si l'alerte est visible via l'API Kibana"""
    try:
        # Vérifier via l'API saved objects
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            "http://localhost:5601/api/saved_objects/_find?type=index-pattern&search=alerts",
            auth=(USER, PASSWORD),
            headers=headers,
            timeout=5,
            verify=False
        )
        
        if response.status_code == 200:
            patterns = response.json().get('saved_objects', [])
            print("\n📊 Index patterns trouvés:")
            for pattern in patterns:
                print(f"   - {pattern['attributes']['title']}")
    
    except:
        print("⚠️  Impossible de vérifier Kibana")

def main():
    print("🚀 Création d'alerte simple")
    print("=" * 40)
    
    # Créer l'alerte
    if create_and_send_alert():
        print("\n✅ Alerte créée avec succès!")
        
        # Vérifier dans Kibana
        check_alert_in_kibana()
        
        print("\n🔗 Liens d'accès:")
        print("   1. Kibana Discover: http://localhost:5601/app/discover")
        print("      → Sélectionnez un index contenant 'alert'")
        print("   2. Créer une visualisation manuelle si nécessaire")
        
        print("\n📝 Pour créer un index pattern manuellement:")
        print("   Aller dans: Management → Kibana → Index Patterns")
        print("   Créer un pattern pour: test-alerts-2025")
    else:
        print("❌ Échec de création d'alerte")

if __name__ == "__main__":
    main()