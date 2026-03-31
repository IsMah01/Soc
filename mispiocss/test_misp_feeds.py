#!/usr/bin/env python3
"""
Script de test des feeds MISP
Teste l'accessibilité et la validité de chaque feed
"""

import requests
import json
import csv
import datetime
import time

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FEEDS = [
    {"id": 1,  "nom": "CIRCL OSINT Feed",                  "format": "misp",     "provider": "CIRCL",            "url": "https://www.circl.lu/doc/misp/feed-osint/"},
    {"id": 2,  "nom": "The Botvrij.eu Data",               "format": "misp",     "provider": "Botvrij.eu",       "url": "https://www.botvrij.eu/data/feed-osint/"},
    {"id": 3,  "nom": "abuse.ch URLhaus",                  "format": "misp",     "provider": "abuse.ch",         "url": "https://urlhaus.abuse.ch/downloads/misp/"},
    {"id": 4,  "nom": "abuse.ch ThreatFox",                "format": "misp",     "provider": "abuse.ch",         "url": "https://threatfox.abuse.ch/export/misp/"},
    {"id": 5,  "nom": "abuse.ch MalwareBazaar",            "format": "misp",     "provider": "abuse.ch",         "url": "https://bazaar.abuse.ch/export/misp/"},
    {"id": 6,  "nom": "abuse.ch Feodo Tracker C2",         "format": "misp",     "provider": "abuse.ch",         "url": "https://feodotracker.abuse.ch/downloads/misp.json"},
    {"id": 7,  "nom": "Cisco Talos Intelligence",          "format": "freetext", "provider": "Cisco Talos",      "url": "https://www.talosintelligence.com/documents/ip-blacklist"},
    {"id": 8,  "nom": "Emerging Threats Compromised IPs",  "format": "freetext", "provider": "Emerging Threats", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
    {"id": 9,  "nom": "Proofpoint ET Block IPs",           "format": "freetext", "provider": "Proofpoint ET",    "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"},
    {"id": 10, "nom": "Spamhaus DROP",                     "format": "freetext", "provider": "Spamhaus",         "url": "https://www.spamhaus.org/drop/drop.txt"},
    {"id": 11, "nom": "Spamhaus EDROP",                    "format": "freetext", "provider": "Spamhaus",         "url": "https://www.spamhaus.org/drop/edrop.txt"},
    {"id": 12, "nom": "FireHOL Level 1",                   "format": "freetext", "provider": "FireHOL",          "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
    {"id": 13, "nom": "FireHOL Level 2",                   "format": "freetext", "provider": "FireHOL",          "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"},
    {"id": 14, "nom": "IPsum Level 3",                     "format": "freetext", "provider": "IPsum",            "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
    {"id": 15, "nom": "OpenPhish",                         "format": "freetext", "provider": "OpenPhish",        "url": "https://openphish.com/feed.txt"},
    {"id": 16, "nom": "Digital Side Threat Intel",         "format": "misp",     "provider": "Digital Side",     "url": "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/"},
    {"id": 17, "nom": "Tor Exit Nodes",                    "format": "freetext", "provider": "dan.me.uk",        "url": "https://www.dan.me.uk/torlist/?exit"},
    {"id": 18, "nom": "Blocklist.de All Attacks",          "format": "freetext", "provider": "Blocklist.de",     "url": "https://lists.blocklist.de/lists/all.txt"},
    {"id": 19, "nom": "Blocklist.de SSH",                  "format": "freetext", "provider": "Blocklist.de",     "url": "https://lists.blocklist.de/lists/ssh.txt"},
    {"id": 20, "nom": "Blocklist.de RDP",                  "format": "freetext", "provider": "Blocklist.de",     "url": "https://lists.blocklist.de/lists/rdp.txt"},
    {"id": 21, "nom": "ESET Malware IOC",                  "format": "misp",     "provider": "ESET",             "url": "https://raw.githubusercontent.com/eset/malware-ioc/master/"},
    {"id": 22, "nom": "ViriBack C2 Tracker",               "format": "misp",     "provider": "ViriBack",         "url": "https://raw.githubusercontent.com/viriback/tracker/master/"},
    {"id": 23, "nom": "Unit42 Ransomware IOCs",            "format": "misp",     "provider": "Palo Alto Unit42", "url": "https://raw.githubusercontent.com/pan-unit42/iocs/master/"},
    {"id": 24, "nom": "CISA Known Exploited Vulns",        "format": "freetext", "provider": "CISA",             "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    {"id": 25, "nom": "NCC Group Cyber Defence",           "format": "misp",     "provider": "NCC Group",        "url": "https://raw.githubusercontent.com/nccgroup/Cyber-Defence/master/"},
    {"id": 26, "nom": "Magecart IOCs Retail",              "format": "freetext", "provider": "Community",        "url": "https://raw.githubusercontent.com/unmanarc/magecart-iocs/main/"},
    {"id": 27, "nom": "TweetFeed URLs",                    "format": "freetext", "provider": "TweetFeed",        "url": "https://api.tweetfeed.live/v1/month/urls"},
    {"id": 28, "nom": "TweetFeed IPs",                     "format": "freetext", "provider": "TweetFeed",        "url": "https://api.tweetfeed.live/v1/month/ip"},
    {"id": 29, "nom": "TweetFeed Hashes",                  "format": "freetext", "provider": "TweetFeed",        "url": "https://api.tweetfeed.live/v1/month/sha256"},
    {"id": 30, "nom": "C2IntelFeeds IPs",                  "format": "freetext", "provider": "drb-ra",           "url": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv"},
    {"id": 31, "nom": "Cyber Cure IPs",                    "format": "freetext", "provider": "CyberCure",        "url": "https://www.cybercure.ai/feeds/ips.txt"},
    {"id": 32, "nom": "Cyber Cure Hashes",                 "format": "freetext", "provider": "CyberCure",        "url": "https://www.cybercure.ai/feeds/hash.txt"},
    {"id": 33, "nom": "VX Vault URLs",                     "format": "freetext", "provider": "VX Vault",         "url": "http://vxvault.net/URL_List.php"},
]

HEADERS = {"User-Agent": "Mozilla/5.0 (MISP Feed Tester) Python/3.x"}

def get_emoji(statut):
    return {"OK": "✅", "PARTIEL": "⚠️", "KO": "❌"}.get(statut, "❓")

def compter_lignes(contenu):
    return len([l for l in contenu.splitlines()
                if l.strip() and not l.strip().startswith(("#", ";"))])

def tester_misp(url, timeout=15):
    manifest_url = url.rstrip("/") + "/manifest.json"
    try:
        r = requests.get(manifest_url, headers=HEADERS, timeout=timeout, verify=False)
        if r.status_code == 200:
            data = r.json()
            nb = len(data) if isinstance(data, dict) else 0
            return "OK", nb, f"manifest.json OK ({nb} événements)"
    except Exception:
        pass
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and "Event" in data:
                    nb = len(data["Event"].get("Attribute", []))
                    return "OK", nb, f"Event MISP direct ({nb} attributs)"
                return "PARTIEL", 0, "JSON valide, format inattendu"
            except Exception:
                pass
            if "<html" in r.text.lower():
                return "PARTIEL", 0, "Page HTML - vérifier manuellement"
            return "PARTIEL", 0, f"HTTP {r.status_code} - contenu non parsé"
        return "KO", 0, f"HTTP {r.status_code}"
    except requests.exceptions.ConnectionError:
        return "KO", 0, "Connexion refusée"
    except requests.exceptions.Timeout:
        return "KO", 0, "Timeout"
    except Exception as e:
        return "KO", 0, str(e)[:60]

def tester_freetext(url, timeout=15):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        if r.status_code == 200:
            nb = compter_lignes(r.text)
            if nb > 0:
                return "OK", nb, f"{nb} entrées récupérées"
            try:
                data = r.json()
                if isinstance(data, list):
                    return "OK", len(data), f"{len(data)} entrées JSON"
                return "PARTIEL", 0, "JSON dict - vérifier structure"
            except Exception:
                pass
            return "PARTIEL", 0, "Contenu vide ou non reconnu"
        return "KO", 0, f"HTTP {r.status_code}"
    except requests.exceptions.ConnectionError:
        return "KO", 0, "Connexion refusée"
    except requests.exceptions.Timeout:
        return "KO", 0, "Timeout"
    except Exception as e:
        return "KO", 0, str(e)[:60]

def tester(feed):
    print(f"  [{feed['id']:02d}] {feed['nom'][:42]:<42}", end="", flush=True)
    debut = time.time()
    if feed["format"] == "misp":
        statut, nb, detail = tester_misp(feed["url"])
    else:
        statut, nb, detail = tester_freetext(feed["url"])
    duree = round(time.time() - debut, 2)
    print(f" {get_emoji(statut)} {statut:<7} | {nb:>7} IOCs | {detail}")
    return {
        "ID": feed["id"], "Nom": feed["nom"], "Format": feed["format"],
        "Provider": feed["provider"], "URL": feed["url"],
        "Statut": statut, "Nb_IOCs": nb, "Detail": detail,
        "Duree_s": duree,
        "Date_test": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Recommandation": {
            "OK": "Conserver", "PARTIEL": "Vérifier manuellement", "KO": "Remplacer / Supprimer"
        }.get(statut, "")
    }

def resume(resultats):
    ok      = sum(1 for r in resultats if r["Statut"] == "OK")
    partiel = sum(1 for r in resultats if r["Statut"] == "PARTIEL")
    ko      = sum(1 for r in resultats if r["Statut"] == "KO")
    total   = sum(r["Nb_IOCs"] for r in resultats)
    print("\n" + "="*65)
    print("                       RÉSUMÉ")
    print("="*65)
    print(f"  ✅ Fonctionnels  : {ok}")
    print(f"  ⚠️  Partiels      : {partiel}")
    print(f"  ❌ Défaillants   : {ko}")
    print(f"  📊 Total IOCs    : {total:,}")
    print("="*65)
    if ko:
        print("\n❌ Feeds défaillants à remplacer :")
        for r in resultats:
            if r["Statut"] == "KO":
                print(f"   [{r['ID']:02d}] {r['Nom']} → {r['Detail']}")

def main():
    print("="*65)
    print("      AUDIT COMPLET DES FEEDS MISP")
    print(f"      {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*65 + "\n")

    resultats = []
    for feed in FEEDS:
        resultats.append(tester(feed))
        time.sleep(0.3)

    resume(resultats)

    fichier = "audit_feeds_misp.csv"
    champs = ["ID","Nom","Format","Provider","URL","Statut","Nb_IOCs","Detail","Duree_s","Date_test","Recommandation"]
    with open(fichier, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=champs)
        writer.writeheader()
        writer.writerows(resultats)
    print(f"\n📄 Résultats exportés : {fichier}")
    print("✅ Audit terminé.")

if __name__ == "__main__":
    main()
