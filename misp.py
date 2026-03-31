from pymisp import PyMISP
from elasticsearch import Elasticsearch
from datetime import datetime


# Paramètres MISP
misp_url = "https://localhost:8443"
misp_key = "iMvI3fUlWLY01OQz4Qk6X6ZLTQcQVl6dGXsVwc5w"
misp_verifycert = False  # False si certificat self-signed

# Connexion à MISP
misp = PyMISP(misp_url, misp_key, misp_verifycert)

# Connexion à Elasticsearch
es = Elasticsearch("http://elastic:changeme123@localhost:9200")

# Récupération des attributs depuis MISP
attributes = misp.search(controller='attributes', return_format='json', include_attachments=True)

for attr in attributes['Attribute']:
    doc = {
        "ioc_value": attr["value"],
        "ioc_type": attr["type"],
        "category": attr["category"],
        "event_id": attr["event_id"],
        "uuid": attr["uuid"],
        "@timestamp": datetime.utcnow().isoformat()  # ou datetime.now(timezone.utc)
    }
    # Indexation dans Elasticsearch
    es.index(index="misp_iocs", document=doc)

print("Import MISP -> Elasticsearch terminé !")
