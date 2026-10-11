#!/usr/bin/env python3
"""
Surveille les alertes IDS dans Elasticsearch et notifie l'administrateur
via un webhook Discord dès qu'un cas est jugé "confirmé" (priorité critique, dédupliqué).
"""
import os
import sys
import time
import logging
from datetime import datetime, timezone

import requests

# --- Configuration (lue depuis l'environnement, voir .env) -----------------
ES_URL = os.environ.get("ES_URL", "http://127.0.0.1:9200")
ES_USER = os.environ["ELASTIC_ALERT_USER"]
ES_PASSWORD = os.environ["ELASTIC_ALERT_PASSWORD"]

DISCORD_WEBHOOK_URL = os.environ["DISCORD_WEBHOOK_URL"]

PRIORITY_THRESHOLD = int(os.environ.get("ALERT_PRIORITY_THRESHOLD", "1"))
DEDUP_SECONDS = int(os.environ.get("ALERT_DEDUP_MINUTES", "10")) * 60
POLL_SECONDS = int(os.environ.get("ALERT_POLL_SECONDS", "30"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("watch-alerts")

_last_sent = {}
_last_checked_iso = None


def query_new_alerts():
    global _last_checked_iso
    now = datetime.now(timezone.utc)
    gte = _last_checked_iso or (now.isoformat())

    body = {
        "size": 100,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gt": gte}}},
                    {"range": {"priority": {"lte": PRIORITY_THRESHOLD}}},
                ]
            }
        },
    }
    r = requests.post(
        f"{ES_URL}/ids-alerts-*/_search",
        json=body,
        auth=(ES_USER, ES_PASSWORD),
        timeout=10,
    )
    r.raise_for_status()
    hits = r.json()["hits"]["hits"]
    if hits:
        _last_checked_iso = hits[-1]["_source"]["@timestamp"]
    else:
        _last_checked_iso = now.isoformat()
    return [h["_source"] for h in hits]


def is_duplicate(alert):
    key = (alert.get("signature"), alert.get("src_ip"))
    last = _last_sent.get(key)
    now = time.time()
    if last and (now - last) < DEDUP_SECONDS:
        return True
    _last_sent[key] = now
    return False


def format_message(alert):
    ts = alert.get("@timestamp", "?")
    return (
        f"🚨 **[CRITIQUE] {alert.get('signature', 'Alerte IDS')}**\n"
        f"**Quand** : {ts}\n"
        f"**Source** : `{alert.get('src_ip', '?')}:{alert.get('src_port', '?')}`\n"
        f"**Cible** : `{alert.get('dest_ip', '?')}:{alert.get('dest_port', '?')}`\n"
        f"**Détail** : priorité {alert.get('priority')}, sid {alert.get('signature_id')}\n"
        f"**Classe** : {alert.get('classification', '?')}\n"
        f"**Action** : vérifier le dashboard Kibana, envisager de bloquer l'IP source\n"
        f"**Lien** : http://localhost:5601/app/discover"
    )


def send_discord(text):
    r = requests.post(DISCORD_WEBHOOK_URL, json={"content": text}, timeout=10)
    r.raise_for_status()


def main():
    log.info("Démarrage de la surveillance (seuil priorité=%s, dédup=%ss)",
              PRIORITY_THRESHOLD, DEDUP_SECONDS)
    while True:
        try:
            for alert in query_new_alerts():
                if is_duplicate(alert):
                    log.info("Alerte dédupliquée: %s depuis %s",
                             alert.get("signature"), alert.get("src_ip"))
                    continue
                send_discord(format_message(alert))
                log.info("Notification envoyée: %s", alert.get("signature"))
        except requests.RequestException as e:
            log.error("Erreur réseau (Elasticsearch ou Discord): %s", e)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
