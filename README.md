# Détection d'intrusions et gestion de logs

Projet universitaire en équipe. Un IDS (Snort 3 ou Suricata) détecte cinq scénarios d'intrusion. Ses alertes et les logs du serveur web victime sont centralisés par syslog-ng, stockés dans Elasticsearch et visualisés dans Kibana.

```
IDS / serveur web  --syslog-ng (601/tcp)-->  collecteur syslog-ng  -->  Elasticsearch  -->  Kibana
```

Schéma détaillé : [docs/architecture.md](docs/architecture.md).

## Composants

| Composant          | Emplacement                  | Version  |
|--------------------|------------------------------|----------|
| Elasticsearch      | Docker, VM `siem-ids`        | 8.19.23  |
| Kibana             | Docker, VM `siem-ids`        | 8.19.23  |
| syslog-ng collecteur | natif, VM `siem-ids`       | 4.8.1    |
| syslog-ng clients  | VM IDS et VM serveur web     |          |
| IDS                | VM IDS                       |          |

## Arborescence

```
configs/syslog-ng/       collector.conf, client-ids.conf, client-web.conf
configs/elasticsearch/   template d'index, rôles syslog-ng et lecture seule
kibana/                  export du dashboard (dashboard.ndjson)
scripts/                 setup-elasticsearch.sh, install-collector.sh,
                         create-data-views.sh, create-viewer.sh, demo-data.py,
                         import-dashboard.sh
scripts/alerting/        watch-alerts.py, siem-alerting.service (notifications Discord)
scripts/alerting/        watch-alerts.py, siem-alerting.service (notifications Discord)
docs/                    architecture, installation, visualisation
screenshots/             captures Kibana
docker-compose.yml       Elasticsearch et Kibana
.env.example             variables à copier dans .env
```

## Mise en place rapide (VM siem-ids)

```bash
cp .env.example .env                   # puis renseigner les mots de passe
docker compose up -d
./scripts/setup-elasticsearch.sh       # utilisateur syslog_ng, template d'index
sudo apt-get install -y syslog-ng-core syslog-ng-mod-http syslog-ng-scl
sudo ./scripts/install-collector.sh
./scripts/create-data-views.sh
./scripts/create-viewer.sh             # compte Kibana lecture seule de l'équipe
```

Accès à Kibana : `ssh -L 5601:127.0.0.1:5601 kenan@100.80.61.14` puis `http://localhost:5601`.

## Documentation

- [Architecture](docs/architecture.md)
- [Installation de syslog-ng (collecteur et clients)](docs/installation/02-syslog-ng.md)
- [Installation d'Elasticsearch et Kibana](docs/installation/03-elk.md)
- [Visualisation](docs/visualisation.md)

## IDS

> À compléter (partie IDS) : choix de l'IDS, installation, règles.

## Scénarios d'intrusion

> À compléter (partie scénarios) : description des cinq scénarios, outils utilisés, résultats attendus.

| # | Scénario | Détection | Index |
|---|----------|-----------|-------|
| 1 |          |           |       |
| 2 |          |           |       |
| 3 |          |           |       |
| 4 |          |           |       |
| 5 |          |           |       |

## Alertes et notifications


Le script `scripts/alerting/watch-alerts.py` interroge Elasticsearch toutes les 30 s et envoie une notification sur un salon Discord (webhook) pour chaque alerte jugée critique.

**Ce qui déclenche une notification**
- alerte de l'index `ids-alerts-*` avec `priority <= ALERT_PRIORITY_THRESHOLD` (1 par défaut, la priorité la plus haute de Snort) ;
- déduplication : une même paire (signature, IP source) n'est notifiée qu'une fois toutes les `ALERT_DEDUP_MINUTES` (10 min), pour éviter d'inonder le salon pendant un scan ou un flood.

Le message contient la signature, l'horodatage, la source, la cible, la priorité, le SID, la classification et l'action recommandée.

**Installation**

```bash
# 1. Rôle et utilisateur Elasticsearch en lecture seule
curl -u "elastic:$ELASTIC_PASSWORD" -X PUT http://127.0.0.1:9200/_security/role/alert_reader_role \
  -H 'Content-Type: application/json' \
  -d '{"indices":[{"names":["ids-alerts-*"],"privileges":["read","view_index_metadata"]}]}'
curl -u "elastic:$ELASTIC_PASSWORD" -X PUT http://127.0.0.1:9200/_security/user/alert_reader \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"$ELASTIC_ALERT_PASSWORD\",\"roles\":[\"alert_reader_role\"]}"

# 2. Renseigner ELASTIC_ALERT_* et DISCORD_WEBHOOK_URL dans .env

# 3. Service systemd
sudo cp scripts/alerting/siem-alerting.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now siem-alerting.service
journalctl -u siem-alerting.service -f
```

**Test** : indexer une alerte factice de priorité 1 dans `ids-alerts-test` avec l'utilisateur `elastic`. La notification arrive sur Discord en moins de 30 s. Supprimer ensuite l'index de test.

