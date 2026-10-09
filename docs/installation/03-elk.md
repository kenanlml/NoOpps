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

Depuis le poste de travail, avec le port 2222 de l'hôte redirigé vers le SSH de la VM :

```bash
ssh -p 2222 -L 5601:127.0.0.1:5601 kenan@<hote>
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
```

### Vérification des droits

```bash
set -a; . ./.env; set +a
U="syslog_ng:$SYSLOG_NG_PASSWORD"
curl -s -u "$U" -H 'Content-Type: application/json' -X POST http://127.0.0.1:9200/syslog-2000.01.01/_doc -d '{"message":"t"}' -o /dev/null -w '%{http_code}\n'   # 201
curl -s -u "$U" -H 'Content-Type: application/json' -X POST http://127.0.0.1:9200/autre/_doc -d '{"a":1}' -o /dev/null -w '%{http_code}\n'               # 403
curl -s -u "$U" http://127.0.0.1:9200/syslog-2000.01.01/_search -o /dev/null -w '%{http_code}\n'                                                         # 403
curl -s -u "$U" -X DELETE http://127.0.0.1:9200/syslog-2000.01.01 -o /dev/null -w '%{http_code}\n'                                                       # 403
```
