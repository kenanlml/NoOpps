# Installation d'Elasticsearch et Kibana

## 1. Docker

Installation depuis le dépôt officiel Docker (le paquet `docker.io` d'Ubuntu ne fournit pas toujours le plugin compose v2).

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu resolute stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker kenan
```

Il faut se reconnecter pour que l'appartenance au groupe `docker` soit prise en compte.

Vérification :

```bash
docker --version          # Docker version 29.9.0
docker compose version    # Docker Compose version v5.6.0
docker run --rm hello-world
```

### vm.max_map_count

Elasticsearch exige `vm.max_map_count >= 262144`. Ubuntu 26.04 le fixe déjà à 1048576 par défaut, donc aucun fichier sysctl n'est ajouté.

```bash
sysctl vm.max_map_count   # vm.max_map_count = 1048576
```

## 2. Elasticsearch et Kibana

Les deux services tournent dans Docker à partir de `docker-compose.yml`, en version 8.19.23 (dernière 8.x disponible).

### Choix de configuration

- `discovery.type=single-node` : un seul nœud, ce qui dispense de configurer le TLS sur le transport.
- `xpack.security.enabled=true` : authentification obligatoire sur l'API.
- `xpack.security.http.ssl.enabled=false` : l'API reste en HTTP. Les ports 9200 et 5601 ne sont publiés que sur `127.0.0.1`, donc rien ne transite sur le réseau. Les clients sont syslog-ng (local) et Kibana (réseau Docker interne). Kibana s'utilise depuis un tunnel SSH.
- `ES_JAVA_OPTS=-Xms2g -Xmx2g` : 2 Go de heap sur 7,2 Go de RAM, pour laisser de la marge à Kibana et au cache système.
- `xpack.ml.enabled=false` : le machine learning n'est pas utilisé et consomme de la mémoire.
- Volumes nommés `esdata` et `kibanadata` pour conserver les données, `restart: unless-stopped` pour redémarrer avec la VM.

Kibana ne peut pas se connecter avec le compte `elastic`. Le service `setup` attend qu'Elasticsearch soit sain, définit le mot de passe de `kibana_system` via l'API puis s'arrête. Kibana ne démarre qu'après sa réussite.

`ENCRYPTION_KEY` sert aux clés de chiffrement de Kibana (saved objects chiffrés, sessions, reporting). Sans elle, les règles d'alerte de Kibana ne sont pas utilisables.

### Mise en place

```bash
cp .env.example .env
# remplacer les valeurs, par exemple avec :
openssl rand -base64 33 | tr -dc 'A-Za-z0-9' | head -c 24
chmod 600 .env
docker compose up -d
```

Le premier lancement télécharge environ 1,2 Go d'images.

### Vérification

```bash
set -a; . ./.env; set +a
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9200        # 401
curl -s -u "elastic:$ELASTIC_PASSWORD" http://127.0.0.1:9200           # "number" : "8.19.23"
curl -s -u "elastic:$ELASTIC_PASSWORD" 'http://127.0.0.1:9200/_cluster/health?filter_path=status'
# {"status":"green"}
curl -s -u "elastic:$ELASTIC_PASSWORD" 'http://127.0.0.1:9200/_nodes/jvm?filter_path=nodes.*.jvm.mem.heap_max_in_bytes'
# heap_max_in_bytes: 2147483648
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5601/api/status   # 200
ss -ltn | grep -E ':(9200|5601)\b'
# 127.0.0.1:5601 et 127.0.0.1:9200 uniquement
```

### Accès à Kibana

Depuis le poste de travail, par SSH sur l'IP Tailscale de la VM :

```bash
ssh -L 5601:127.0.0.1:5601 kenan@100.80.61.14
```

Puis ouvrir `http://localhost:5601` et se connecter avec `elastic`.

## 3. Utilisateur syslog-ng et template d'index

syslog-ng n'utilise pas le compte `elastic`. Il dispose d'un utilisateur dédié, `syslog_ng`, avec le rôle `syslog_ng_writer` (`configs/elasticsearch/role-syslog-ng.json`) :

- aucun privilège cluster ;
- `create_index` et `index` sur `ids-alerts-*`, `web-*` et `syslog-*` uniquement.

Le privilège `index` est nécessaire car `elasticsearch-http()` envoie des actions `index` dans le bulk (`create_doc` ne suffit pas).

Le template `siem` (`configs/elasticsearch/index-template.json`) s'applique aux trois motifs d'index :

- `number_of_replicas: 0` : un seul nœud, sinon les index restent en jaune ;
- `src_ip` et `dest_ip` en type `ip`, ce qui permet les recherches par sous-réseau (`src_ip:"10.10.0.0/24"`) ;
- `@timestamp` en `date`, champ de temps des data views Kibana ;
- `host`, `program`, `signature`, `classification`, etc. en `keyword` pour les agrégations ;
- `raw` contient le JSON d'origine de l'IDS, en mapping dynamique ;
- `date_detection` désactivé : les horodatages Snort (`10/09-20:40:01.123456`) et Suricata (ISO 8601) dans `raw` provoqueraient sinon des conflits de type.

Le mot de passe de `syslog_ng` est dans `.env` (`SYSLOG_NG_PASSWORD`). Le script `scripts/setup-elasticsearch.sh` crée le rôle, l'utilisateur et le template :

```bash
./scripts/setup-elasticsearch.sh
# {"role":{"created":true}}
# {"created":true}
# {"acknowledged":true}
# {"acknowledged":true,"shards_acknowledged":true,"index":"ids-alerts-init"}
# (idem pour web-init et syslog-init)
```

Le script crée aussi trois index vides, `ids-alerts-init`, `web-init` et `syslog-init`, qui reçoivent le mapping du template. Sans index correspondant à leur motif, les data views n'ont aucun champ et le dashboard affiche `Field @timestamp was not found` tant qu'aucun log n'est arrivé. Ces index ne contiennent aucun document et ne faussent pas les comptages.

### Vérification des droits

```bash
set -a; . ./.env; set +a
U="syslog_ng:$SYSLOG_NG_PASSWORD"
curl -s -u "$U" -H 'Content-Type: application/json' -X POST http://127.0.0.1:9200/syslog-2000.01.01/_doc -d '{"message":"t"}' -o /dev/null -w '%{http_code}\n'   # 201
curl -s -u "$U" -H 'Content-Type: application/json' -X POST http://127.0.0.1:9200/autre/_doc -d '{"a":1}' -o /dev/null -w '%{http_code}\n'               # 403
curl -s -u "$U" http://127.0.0.1:9200/syslog-2000.01.01/_search -o /dev/null -w '%{http_code}\n'                                                         # 403
curl -s -u "$U" -X DELETE http://127.0.0.1:9200/syslog-2000.01.01 -o /dev/null -w '%{http_code}\n'                                                       # 403
```

## 4. Kibana : data views et dashboard

### Data views

`scripts/create-data-views.sh` crée une data view par famille d'index via l'API Kibana, avec `@timestamp` comme champ de temps :

| id           | Motif           | Nom          |
|--------------|-----------------|--------------|
| `ids-alerts` | `ids-alerts-*`  | Alertes IDS  |
| `web`        | `web-*`         | Logs web     |
| `syslog`     | `syslog-*`      | Syslog       |

Les id sont fixés pour que le dashboard exporté (`kibana/dashboard.ndjson`) pointe toujours vers les mêmes data views, même après une réinstallation. Le script peut être relancé (`override: true`).

```bash
./scripts/create-data-views.sh
# Alertes IDS (ids-alerts-*): 200
# Logs web (web-*): 200
# Syslog (syslog-*): 200
```

Dans la data view `ids-alerts`, `src_ip` et `dest_ip` sont de type `ip`, `@timestamp` de type `date`.

### Import du dashboard

Le dashboard est exporté dans `kibana/dashboard.ndjson` (détail des panneaux dans [visualisation.md](../visualisation.md)). Pour l'importer sur une autre instance :

```bash
./scripts/import-dashboard.sh                    # kibana/dashboard.ndjson par défaut
./scripts/import-dashboard.sh autre-fichier.ndjson
```

Le script utilise `POST /api/saved_objects/_import?overwrite=true`. Import de `kibana/dashboard.ndjson` testé : `"success":true`, 12 objets.

## 5. Utilisateur Kibana en lecture seule

L'équipe consulte Kibana avec un compte en lecture seule plutôt qu'avec `elastic`. Les identifiants sont dans `.env` (`KIBANA_VIEWER_USER`, par défaut `equipe`, et `KIBANA_VIEWER_PASSWORD`).

Le rôle `siem_viewer` (`configs/elasticsearch/role-siem-viewer.json`) donne :

- côté Elasticsearch : `read` et `view_index_metadata` sur `ids-alerts-*`, `web-*` et `syslog-*`, aucun privilège cluster ;
- côté Kibana, dans tous les espaces : Dashboard, Discover et Visualize en lecture. Les autres fonctionnalités (Stack Management, règles d'alerte, Dev Tools...) ne sont pas accessibles.

Le rôle est créé par l'API Kibana (`PUT /api/security/role/siem_viewer`) : l'API Elasticsearch ne gère pas les privilèges par fonctionnalité Kibana. L'utilisateur est créé par l'API Elasticsearch.

```bash
./scripts/create-viewer.sh
# rôle siem_viewer : 204
# {"created":true}
```

### Vérification

Avec le compte `equipe`, sur un index de test `syslog-2000.01.01` supprimé ensuite :

| Action                                   | Code |
|------------------------------------------|------|
| recherche dans `syslog-*`                | 200  |
| écriture dans `syslog-*`                 | 403  |
| suppression d'un index                   | 403  |
| lecture de `.kibana`                     | 403  |
| liste des utilisateurs Elasticsearch     | 403  |
| liste des data views (Kibana)            | 200  |
| liste des dashboards (Kibana)            | 200  |
| création d'un dashboard                  | 403  |
| création ou suppression d'une data view  | 403  |
| gestion des rôles                        | 403  |
