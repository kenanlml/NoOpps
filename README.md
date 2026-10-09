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
configs/elasticsearch/   template d'index, rôle de l'utilisateur syslog-ng
kibana/                  export du dashboard (dashboard.ndjson)
scripts/                 setup-elasticsearch.sh, install-collector.sh,
                         create-data-views.sh, import-dashboard.sh
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
```

Accès à Kibana : `ssh -L 5601:127.0.0.1:5601 kenan@<vm>` puis `http://localhost:5601`.

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

> À compléter (partie notifications).
