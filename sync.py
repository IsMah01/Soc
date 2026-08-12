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
    "elastic_password": os.getenv("ELASTIC_PASSWORD", "<REMOVED_DEFAULT_PASSWORD>"),

    # IMPORTANT: /api/v1/alert (pas /api/alert)
    "thehive_url": os.getenv("THEHIVE_URL", "http://thehive:9000/api/alert"),
    "thehive_key": os.getenv("THEHIVE_API_KEY", "<REMOVED_THEHIVE_API_KEY>"),
    "thehive_org": os.getenv("THEHIVE_ORG", "Soc"),

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


def get_nested(src: dict, path: str, default=None):
    """
    Récupère un champ imbriqué: get_nested(src, "source.ip")
    Supporte aussi les documents qui utilisent des clés ECS plates: {"source.ip": "..."}.
    """
    if path in src:
        return src[path]

    current = src
    for part in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(part)
        if current is None:
            return default
    return current


def normalize_severity(severity_value=None, risk_score=None) -> int:
    """
    Convertit la sévérité Elastic vers TheHive:
    TheHive: 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    """
    if isinstance(severity_value, int):
        return max(1, min(4, severity_value))

    if isinstance(severity_value, str):
        sev = severity_value.lower().strip()

        if sev in ["low", "info", "informational"]:
            return 1
        if sev in ["medium", "moderate"]:
            return 2
        if sev == "high":
            return 3
        if sev in ["critical", "crit"]:
            return 4
        if sev.isdigit():
            return max(1, min(4, int(sev)))

    if isinstance(risk_score, (int, float)):
        if risk_score >= 90:
            return 4
        if risk_score >= 70:
            return 3
        if risk_score >= 40:
            return 2
        return 1

    return 2


def add_observable(
    observables: list,
    data_type: str,
    data,
    message: str,
    ioc: bool = False,
    tags=None,
):
    """
    Ajoute un observable TheHive si la valeur existe.
    """
    if data is None:
        return

    values = data if isinstance(data, list) else [data]

    for value in values:
        if value is None:
            continue

        value = str(value).strip()
        if not value:
            continue

        observable = {
            "dataType": data_type,
            "data": value,
            "message": message,
            "tlp": 2,
            "pap": 2
        }
        if ioc:
            observable["ioc"] = True
        if tags:
            observable["tags"] = tags

        existing = next(
            (
                item for item in observables
                if item.get("dataType") == data_type
                and item.get("data") == value
            ),
            None
        )

        if existing:
            existing_message = existing.get("message", "")
            if message not in existing_message:
                existing["message"] = f"{existing_message}; {message}"
            if ioc:
                existing["ioc"] = True
            if tags:
                existing_tags = set(existing.get("tags", []))
                existing["tags"] = sorted(existing_tags.union(tags))
            continue

        observables.append(observable)


def add_first_observable(
    observables: list,
    data_type: str,
    src: dict,
    paths: list[str],
    message: str
):
    """
    Ajoute le premier champ trouvé parmi plusieurs chemins ECS possibles.
    """
    for path in paths:
        value = get_nested(src, path)
        if value not in (None, "", []):
            add_observable(observables, data_type, value, message)
            return


def build_observables(src: dict) -> list:
    """
    Transforme les champs Elastic ECS en observables TheHive.
    """
    observables = []

    add_observable(
        observables,
        "ip",
        get_nested(src, "source.ip"),
        "Source IP from Elastic alert"
    )

    add_observable(
        observables,
        "ip",
        get_nested(src, "client.ip"),
        "Client IP from Elastic alert"
    )

    add_observable(
        observables,
        "ip",
        get_nested(src, "destination.ip"),
        "Destination IP from Elastic alert"
    )

    add_observable(
        observables,
        "ip",
        get_nested(src, "related.ip"),
        "Related IP from Elastic alert"
    )

    url_original = (
        get_nested(src, "url.original")
        or get_nested(src, "url.full")
    )
    if url_original:
        if str(url_original).startswith(("http://", "https://")):
            add_observable(
                observables,
                "url",
                url_original,
                "Targeted URL from Elastic alert"
            )
        else:
            add_observable(
                observables,
                "other",
                url_original,
                "Targeted URL/path from Elastic alert"
            )

    add_observable(
        observables,
        "other",
        get_nested(src, "url.path"),
        "Targeted URL path from Elastic alert"
    )

    add_observable(
        observables,
        "fqdn",
        get_nested(src, "url.domain"),
        "Target domain from Elastic alert"
    )

    add_observable(
        observables,
        "hostname",
        get_nested(src, "host.name"),
        "Host from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "user_agent.original",
            "user_agent.name",
            "user_agent.device.name",
        ],
        "User-Agent from Elastic alert"
    )

    add_first_observable(
        observables,
        "mail",
        src,
        [
            "user.email",
            "user.mail",
            "source.user.email",
            "target.user.email",
            "o365.audit.UserId",
            "office365.audit.UserId",
        ],
        "User email from Elastic alert"
    )

    add_observable(
        observables,
        "mail",
        get_nested(src, "o365.audit.TargetUserOrGroupName")
        or get_nested(src, "office365.audit.TargetUserOrGroupName"),
        "External sharing recipient from Elastic alert"
    )

    add_observable(
        observables,
        "mail",
        get_nested(src, "threat.indicator.email.address"),
        "Known malicious email indicator from Elastic alert",
        ioc=True,
        tags=["malicious-email", "threat-indicator"]
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "threat.indicator.description"),
        "Threat indicator context from Elastic alert",
        ioc=True,
        tags=["threat-indicator"]
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "user.name",
            "user.id",
            "source.user.name",
            "target.user.name",
        ],
        "User identifier from Elastic alert"
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "event.action"),
        "Event action from Elastic alert"
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "event.provider"),
        "Event provider from Elastic alert"
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "event.dataset"),
        "Event dataset from Elastic alert"
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "http.response.status_code"),
        "HTTP response status code from Elastic alert"
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "http.request.method"),
        "HTTP request method from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "file.name",
            "file.path",
            "o365.audit.ObjectId",
            "office365.audit.ObjectId",
        ],
        "File or object name from Elastic alert"
    )

    add_first_observable(
        observables,
        "hostname",
        src,
        [
            "device.name",
            "device.hostname",
            "observer.hostname",
        ],
        "Device name from Elastic alert"
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "source.geo.country_name"),
        "Source country from Elastic alert"
    )

    add_observable(
        observables,
        "other",
        get_nested(src, "source.geo.city_name"),
        "Source city from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "sharing.count",
            "o365.audit.SharingCount",
            "office365.audit.SharingCount",
        ],
        "Sharing link count from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "sharing.scope",
            "o365.audit.SharingScope",
            "office365.audit.SharingScope",
        ],
        "Sharing scope from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "sharing.link_type",
            "o365.audit.LinkType",
            "office365.audit.LinkType",
        ],
        "Sharing link type from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "sharing.external_recipient_count",
            "o365.audit.ExternalRecipientCount",
            "office365.audit.ExternalRecipientCount",
        ],
        "External recipient count from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "session.status",
            "event.outcome",
            "o365.audit.ResultStatus",
            "office365.audit.ResultStatus",
        ],
        "Session or event status from Elastic alert"
    )

    add_first_observable(
        observables,
        "other",
        src,
        [
            "data.sensitivity",
            "file.Ext.sensitivity",
            "labels.sensitivity",
        ],
        "Data sensitivity from Elastic alert"
    )

    return observables


def create_thehive_alert(es_doc: dict, fingerprint: str) -> dict:
    src = es_doc.get("_source", {})
    es_id = es_doc.get("_id", "")
    ts = src.get("@timestamp", "")
    date_ms = iso_to_ms(ts)
    kind = detect_kind(es_doc)
    observables = build_observables(src)

    title = "Alerte Elastic"
    description = ""
    severity = 2

    if kind == "siem-signals":
        rule = src.get("signal", {}).get("rule", {}) or {}
        title = (rule.get("name") or "Alerte Elastic SIEM")[:150]
        severity = normalize_severity(rule.get("severity"), rule.get("risk_score"))
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
        severity = normalize_severity(alert.get("severity"), alert.get("risk_score"))

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
        "severity": severity,
        "date": date_ms,
        "tags": tags,
        "tlp": 2,
        "pap": 2,
        "observables": observables,
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
                    log(f"  observables={len(th_alert.get('observables', []))}")
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
