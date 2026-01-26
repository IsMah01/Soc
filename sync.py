#!/usr/bin/env python3
"""
Script de synchronisation Elastic → TheHive

- Supporte 2 formats Elastic :
  1) .siem-signals-default-* (signal.rule.*)
  2) .alerts-security.alerts-* (kibana.alert.*)

- Évite les doublons via state_file + sourceRef unique
- Envoie dans une organisation TheHive via header X-Organisation
"""

import os
import sys
import time
import json
import hashlib
import requests
from datetime import datetime
from base64 import b64encode

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    "elastic_host": os.getenv("ELASTIC_HOST", "http://elasticsearch:9200"),
    "elastic_user": os.getenv("ELASTIC_USER", "elastic"),
    "elastic_password": os.getenv("ELASTIC_PASSWORD", "changeme123"),

    # IMPORTANT: /api/v1/alert (pas /api/alert)
    "thehive_url": os.getenv("THEHIVE_URL", "http://thehive:9000/api/v1/alert"),
    "thehive_key": os.getenv("THEHIVE_API_KEY", "KThJbjnBKMWCHWT0MDmmAHvpA9Jlmkx1"),
    "thehive_org": os.getenv("THEHIVE_ORG", "SOC-LAB"),

    # Index Elastic
    "siem_signals_index": os.getenv("SIEM_SIGNALS_INDEX", ".siem-signals-default-*"),
    "alerts_security_index": os.getenv("ALERTS_SECURITY_INDEX", ".alerts-security.alerts-*"),

    # State & polling
    "state_file": "/data/sync_state.json",
    "check_interval": int(os.getenv("CHECK_INTERVAL", "30")),     # secondes
    "lookback_minutes": int(os.getenv("LOOKBACK_MINUTES", "5")),  # minutes

    # limites
    "page_size": int(os.getenv("PAGE_SIZE", "50")),
}

# ============================================================================
# UTILITAIRES
# ============================================================================

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)

def get_elastic_headers():
    auth = b64encode(f"{CONFIG['elastic_user']}:{CONFIG['elastic_password']}".encode()).decode()
    return {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth}",
    }

def get_thehive_headers():
    # TheHive v5: Bearer + X-Organisation (si tu veux SOC-LAB)
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {CONFIG['thehive_key']}",
        "X-Organisation": CONFIG["thehive_org"],
    }

def iso_to_ms(iso_ts: str) -> int:
    try:
        if not iso_ts:
            return int(time.time() * 1000)
        # Supporte Z
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)

def md5_16(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:16]

# ============================================================================
# ÉTAT (anti-doublons)
# ============================================================================

def load_state():
    try:
        with open(CONFIG["state_file"], "r") as f:
            st = json.load(f)
            processed = set(st.get("processed_ids", []))
            log(f"État chargé: {len(processed)} IDs traités")
            return processed
    except FileNotFoundError:
        log("Nouvel état: aucun fichier, démarrage à zéro")
        return set()
    except Exception as e:
        log(f"Erreur lecture état: {e} (démarrage à zéro)", "WARNING")
        return set()

def save_state(processed_ids):
    try:
        st = {
            "processed_ids": list(processed_ids),
            "updated": datetime.now().isoformat(),
            "total_processed": len(processed_ids),
        }
        with open(CONFIG["state_file"], "w") as f:
            json.dump(st, f, indent=2)
        log(f"État sauvegardé: {len(processed_ids)} IDs")
    except Exception as e:
        log(f"Erreur sauvegarde état: {e}", "ERROR")

# ============================================================================
# TESTS CONNEXIONS
# ============================================================================

def test_connections():
    log("Test des connexions...")

    # Elasticsearch
    try:
        r = requests.get(
            f"{CONFIG['elastic_host']}/_cat/health?format=json",
            headers=get_elastic_headers(),
            timeout=10,
        )
        if r.status_code == 200:
            h = r.json()[0]
            log(f"Elastic: ✓ ({h.get('status', 'unknown')})")
        else:
            log(f"Elastic: ✗ HTTP {r.status_code} => {r.text[:120]}", "ERROR")
            return False
    except Exception as e:
        log(f"Elastic: ✗ {e}", "ERROR")
        return False

    # TheHive (endpoint public sans auth : /api/status, mais on teste aussi l’API key)
    try:
        r0 = requests.get("http://thehive:9000/api/status", timeout=10)
        if r0.status_code == 200:
            log("TheHive: ✓ (/api/status)")
        else:
            log(f"TheHive: ✗ /api/status HTTP {r0.status_code}", "ERROR")
            return False

        r = requests.get(
            "http://thehive:9000/api/v1/user/current",
            headers=get_thehive_headers(),
            timeout=10,
        )
        if r.status_code == 200:
            u = r.json()
            log(f"TheHive API key: ✓ (login={u.get('login')}, org={u.get('defaultOrganisation')})")
        else:
            log(f"TheHive API key: ✗ HTTP {r.status_code} => {r.text[:120]}", "ERROR")
            return False
    except Exception as e:
        log(f"TheHive: ✗ {e}", "ERROR")
        return False

    return True

# ============================================================================
# FETCH ELASTIC
# ============================================================================

def es_search(index: str, query: dict):
    try:
        url = f"{CONFIG['elastic_host']}/{index}/_search"
        r = requests.post(url, headers=get_elastic_headers(), json=query, timeout=20)
        if r.status_code == 200:
            data = r.json()
            hits = data.get("hits", {}).get("hits", [])
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            return hits, total, None
        return [], 0, f"HTTP {r.status_code}: {r.text[:160]}"
    except Exception as e:
        return [], 0, str(e)

def fetch_siem_signals():
    # Pour .siem-signals-default-* : champ signal.rule
    q = {
        "query": {
            "bool": {
                "must": [{"exists": {"field": "signal.rule"}}],
                "filter": [{
                    "range": {"@timestamp": {"gte": f"now-{CONFIG['lookback_minutes']}m", "lte": "now"}}
                }]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": CONFIG["page_size"],
    }
    hits, total, err = es_search(CONFIG["siem_signals_index"], q)
    if err:
        log(f"Elastic SIEM signals: {err}", "WARNING")
    else:
        log(f"Elastic SIEM signals: {len(hits)} hits ({total} total)")
    return hits

def fetch_alerts_security():
    # Pour .alerts-security.alerts-* : champs kibana.alert.*
    q = {
        "query": {
            "bool": {
                "filter": [{
                    "range": {"@timestamp": {"gte": f"now-{CONFIG['lookback_minutes']}m", "lte": "now"}}
                }]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": CONFIG["page_size"],
    }
    hits, total, err = es_search(CONFIG["alerts_security_index"], q)
    if err:
        log(f"Elastic alerts-security: {err}", "WARNING")
    else:
        log(f"Elastic alerts-security: {len(hits)} hits ({total} total)")
    return hits

# ============================================================================
# MAPPING -> THEHIVE ALERT
# ============================================================================

def detect_kind(es_doc: dict) -> str:
    src = es_doc.get("_source", {})
    if "signal" in src and isinstance(src.get("signal"), dict) and src["signal"].get("rule"):
        return "siem-signals"
    if "kibana" in src and isinstance(src.get("kibana"), dict) and src["kibana"].get("alert"):
        return "alerts-security"
    return "unknown"

def make_fingerprint(es_doc: dict) -> str:
    src = es_doc.get("_source", {})
    _id = es_doc.get("_id", "")
    ts = src.get("@timestamp", "")

    kind = detect_kind(es_doc)
    if kind == "siem-signals":
        rule = src.get("signal", {}).get("rule", {})
        rid = rule.get("id", "") or rule.get("rule_id", "") or rule.get("name", "")
        base = f"siem:{_id}:{rid}:{ts}"
        return md5_16(base)

    if kind == "alerts-security":
        rule_name = src.get("kibana", {}).get("alert", {}).get("rule", {}).get("name", "")
        rule_uuid = src.get("kibana", {}).get("alert", {}).get("rule", {}).get("uuid", "")
        base = f"alerts:{_id}:{rule_uuid}:{rule_name}:{ts}"
        return md5_16(base)

    return md5_16(f"unknown:{_id}:{ts}")

def create_thehive_alert(es_doc: dict, fingerprint: str) -> dict:
    src = es_doc.get("_source", {})
    es_id = es_doc.get("_id", "")
    ts = src.get("@timestamp", "")
    date_ms = iso_to_ms(ts)
    kind = detect_kind(es_doc)

    title = "Alerte Elastic"
    description = ""
    severity = 2

    if kind == "siem-signals":
        rule = src.get("signal", {}).get("rule", {}) or {}
        title = (rule.get("name") or "Alerte Elastic SIEM")[:150]
        severity = src.get("signal", {}).get("severity", 2) or 2
        description = f"""**Alerte Elastic (SIEM signals)**

**Règle:** {rule.get('name', 'Inconnu')}
**Description:** {rule.get('description', 'Pas de description')}

**Détails:**
- Index: {es_doc.get('_index', 'N/A')}
- ID Elastic: {es_id}
- Timestamp: {ts}
- Sévérité: {severity}

**Importé automatiquement le:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""

        tags = ["elastic", "siem-signals", "auto-import"]

    elif kind == "alerts-security":
        alert = src.get("kibana", {}).get("alert", {}) or {}
        rule = alert.get("rule", {}) or {}
        title = (rule.get("name") or "Alerte Elastic Security")[:150]

        # si pas de severity, on essaie risk_score
        severity = alert.get("severity")
        if severity is None:
            # convertir risk_score en "severity" 1..4 grossièrement
            rs = alert.get("risk_score")
            if isinstance(rs, (int, float)):
                if rs >= 75:
                    severity = 4
                elif rs >= 50:
                    severity = 3
                elif rs >= 25:
                    severity = 2
                else:
                    severity = 1
            else:
                severity = 2

        description = f"""**Alerte Elastic (alerts-security)**

**Règle:** {rule.get('name', 'Inconnu')}
**UUID:** {rule.get('uuid', 'N/A')}

**Détails:**
- Index: {es_doc.get('_index', 'N/A')}
- ID Elastic: {es_id}
- Timestamp: {ts}
- Sévérité: {severity}

**Importé automatiquement le:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""

        tags = ["elastic", "alerts-security", "auto-import"]

    else:
        tags = ["elastic", "unknown", "auto-import"]
        description = f"Doc Elastic inconnu. index={es_doc.get('_index')} id={es_id}"

    # sourceRef DOIT être unique dans TheHive
    source_ref = f"{es_id}:{fingerprint}"

    return {
        "type": "elastic",
        "source": "Elastic Security",
        "sourceRef": source_ref,
        "title": title,
        "description": description,
        "severity": int(severity) if str(severity).isdigit() else 2,
        "date": date_ms,
        "tags": tags,
        "tlp": 2,
        "pap": 2,
    }

# ============================================================================
# ENVOI THEHIVE
# ============================================================================

def send_to_thehive(alert: dict):
    try:
        r = requests.post(
            CONFIG["thehive_url"],
            headers=get_thehive_headers(),
            json=alert,
            timeout=20,
        )
        if r.status_code in (200, 201):
            return True, None

        # TheHive renvoie souvent 400 si sourceRef existe déjà
        if r.status_code == 400:
            txt = r.text.lower()
            if "already exists" in txt or "duplicate" in txt or "conflict" in txt:
                return False, "already exists"
            return False, f"HTTP 400: {r.text[:200]}"

        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)

# ============================================================================
# MAIN
# ============================================================================

def main():
    log("=" * 60)
    log("🚀 SYNC ELASTIC → THEHIVE - DÉMARRAGE")
    log("=" * 60)
    log(f"Elastic: {CONFIG['elastic_host']}")
    log(f"TheHive: {CONFIG['thehive_url']} (org={CONFIG['thehive_org']})")
    log(f"Indexes: {CONFIG['siem_signals_index']} + {CONFIG['alerts_security_index']}")
    log(f"Intervalle: {CONFIG['check_interval']}s | Lookback: {CONFIG['lookback_minutes']}m | Size: {CONFIG['page_size']}")
    log("=" * 60)

    if not test_connections():
        log("Connexions échouées. Arrêt.", "ERROR")
        sys.exit(1)

    processed_ids = load_state()

    cycle = 0
    while True:
        cycle += 1
        log(f"Cycle #{cycle} démarré")

        try:
            docs = []
            docs.extend(fetch_siem_signals())
            docs.extend(fetch_alerts_security())

            if not docs:
                log("Aucune nouvelle alerte détectée")
            else:
                new_docs = 0
                sent = 0
                errs = 0

                for d in docs:
                    es_id = d.get("_id")
                    if not es_id:
                        continue

                    if es_id in processed_ids:
                        continue

                    new_docs += 1
                    fp = make_fingerprint(d)
                    kind = detect_kind(d)

                    # récupérer un nom de règle lisible
                    src = d.get("_source", {})
                    if kind == "siem-signals":
                        rule_name = src.get("signal", {}).get("rule", {}).get("name", "Inconnu")
                    elif kind == "alerts-security":
                        rule_name = src.get("kibana", {}).get("alert", {}).get("rule", {}).get("name", "Inconnu")
                    else:
                        rule_name = "Inconnu"

                    log(f"Nouvelle alerte: kind={kind} rule={str(rule_name)[:80]}")
                    log(f"  id={es_id} fp={fp}")

                    th_alert = create_thehive_alert(d, fp)
                    ok, err = send_to_thehive(th_alert)

                    if ok:
                        processed_ids.add(es_id)
                        sent += 1
                        log("  ✓ Envoyée à TheHive")
                    else:
                        if err == "already exists":
                            processed_ids.add(es_id)
                            log("  ⏭️  Déjà existante dans TheHive, marquée comme traitée")
                        else:
                            errs += 1
                            log(f"  ✗ Erreur TheHive: {err}", "WARNING")

                if new_docs > 0:
                    save_state(processed_ids)
                    log(f"Résumé cycle: {sent}/{new_docs} envoyées | erreurs={errs}")

        except KeyboardInterrupt:
            log("Arrêt manuel demandé", "INFO")
            break
        except Exception as e:
            log(f"Erreur inattendue: {e}", "ERROR")
            import traceback
            traceback.print_exc()

        log(f"Attente de {CONFIG['check_interval']} secondes...")
        time.sleep(CONFIG["check_interval"])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Script arrêté par l'utilisateur", "INFO")
    except Exception as e:
        log(f"Erreur fatale: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)
