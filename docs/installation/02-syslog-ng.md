# Installation de syslog-ng

syslog-ng est installé nativement sur la VM `siem-ids` (pas dans Docker). Il reçoit les logs des autres VM et les envoie dans Elasticsearch.

## Réseau

La VM tourne sous VMware (interface `ens33`, `172.16.24.110`) et a Tailscale installé directement (`100.80.61.14`). Les clients envoient leurs logs à cette IP Tailscale, sans redirection de ports :

| Port    | Usage                                           |
|---------|-------------------------------------------------|
| 601/tcp | syslog RFC 5424 sur TCP, transport à privilégier |
| 514/udp | syslog classique, en secours                    |

Elasticsearch (9200) et Kibana (5601) restent sur `127.0.0.1`. Aucun pare-feu n'est configuré pour l'instant.

## 1. Collecteur

### Paquets

```bash
sudo apt-get install -y syslog-ng-core syslog-ng-mod-http syslog-ng-scl
```

- `syslog-ng-core` remplace `rsyslog` (les deux paquets sont en conflit). syslog-ng prend donc aussi en charge les logs locaux, avec la config Ubuntu par défaut.
- `syslog-ng-mod-http` fournit le module HTTP utilisé par `elasticsearch-http()`.
- `syslog-ng-scl` contient la bibliothèque de configuration (`elasticsearch-http()`, `apache-accesslog-parser()`). Sans ce paquet, ces deux blocs sont inconnus et la config ne se charge pas.

Version installée : 4.8.1.

### Configuration

La config est dans `configs/syslog-ng/collector.conf` et s'installe dans `/etc/syslog-ng/conf.d/`, que `/etc/syslog-ng/syslog-ng.conf` inclut déjà. Les identifiants Elasticsearch sont dans `/etc/syslog-ng/es-credentials.conf` (root, 0600), hors du dépôt (modèle : `configs/syslog-ng/es-credentials.conf.example`).

`scripts/install-collector.sh` copie la config, génère le fichier d'identifiants à partir de `.env`, vérifie la syntaxe et redémarre le service :

```bash
cd ~/siem-repo && sudo ./scripts/install-collector.sh
```

### Choix

**Sources.** Sur 601/tcp, le pilote `syslog()` attend du RFC 5424 avec octet counting, ce qu'envoient les clients syslog-ng. Sur 514/udp, un client peut envoyer du RFC 3164 ou du RFC 5424 : la source lit le message brut (`flags(no-parse)`) et le chemin de log choisit le parseur selon l'en-tête (`<PRI>1 ` pour RFC 5424). Sans cette détection, un message RFC 5424 reçu en UDP était mal découpé (programme lu comme `1`).

**Nom d'hôte.** `keep-hostname(yes)` garde le hostname d'origine du client plutôt que son IP Tailscale. `use-dns(no)` évite une résolution DNS par message.

**JSON.** Un message qui commence par `{` passe dans `json-parser(prefix("json."))`. Les autres continuent sans modification (canal de secours dans une `junction`, sinon un échec du parseur supprimerait le message).

**Normalisation.** Snort 3 et Suricata n'utilisent pas les mêmes noms de champs :

| Champ commun     | Snort 3 (alert_json) | Suricata (eve.json)   |
|------------------|----------------------|-----------------------|
| `src_ip`         | `src_addr`           | `src_ip`              |
| `dest_ip`        | `dst_addr`           | `dest_ip`             |
| `src_port`       | `src_port`           | `src_port`            |
| `dest_port`      | `dst_port`           | `dest_port`           |
| `signature`      | `msg`                | `alert.signature`     |
| `signature_id`   | `sid`                | `alert.signature_id`  |
| `priority`       | `priority`           | `alert.severity`      |
| `classification` | `class`              | `alert.category`      |

Le JSON complet est conservé sous `raw`.

Pour les logs d'accès Apache, `apache-accesslog-parser()` extrait l'IP cliente (`src_ip`), la méthode, l'URL, le code de retour et le user-agent.

**Routage.**

| Index                   | Condition                                                              |
|-------------------------|------------------------------------------------------------------------|
| `ids-alerts-%Y.%m.%d`   | programme `snort` ou `suricata`, ou JSON contenant une signature       |
| `web-%Y.%m.%d`          | programme commençant par `apache` (`apache-access`, `apache-error`)    |
| `syslog-%Y.%m.%d`       | tout le reste, dont `auth.log` (sshd, sudo) des clients                |

Les programmes `snort`, `suricata`, `apache-access` et `apache-error` sont fixés par les configs client (`program-override()`).

**Envoi vers Elasticsearch.** `elasticsearch-http()` avec l'utilisateur `syslog_ng` (voir [03-elk.md](03-elk.md#3-utilisateur-syslog-ng-et-template-dindex)), par lots de 100 messages ou toutes les 2 secondes. Un disk-buffer de 1 Go dans `/var/lib/syslog-ng` garde les messages si Elasticsearch est arrêté. Ça a été vérifié : des messages rejetés pendant les tests ont été livrés au redémarrage suivant.

Le `body()` du pilote est redéfini. Avec le paquet Ubuntu 4.8.1, `format-json` interprète mal la valeur vide de `index._type=` et produit `"_type":"index._id="` dans la ligne d'action. Elasticsearch 8 rejette alors tout le bulk (`400` dans les logs de syslog-ng). La même config fonctionnait avec l'image Docker officielle 4.8.0.

### Vérification

Écoute :

```bash
ss -ltnu | grep -E ':(601|514)\b'
# udp UNCONN 0.0.0.0:514
# tcp LISTEN 0.0.0.0:601
```

Envoi de messages de test vers l'IP Tailscale, en TCP et en UDP :

```bash
SNORT='{"timestamp":"10/09-20:40:01.123456","proto":"TCP","src_addr":"10.10.0.5","src_port":41001,"dst_addr":"10.10.0.20","dst_port":22,"gid":1,"sid":1000001,"rev":1,"msg":"SSH brute force","class":"attempted-admin","priority":1,"action":"allow"}'
SURI='{"timestamp":"2026-10-09T20:40:02.000000+0000","event_type":"alert","src_ip":"10.10.0.6","src_port":51000,"dest_ip":"10.10.0.20","dest_port":80,"proto":"TCP","alert":{"signature_id":2000002,"signature":"SQL injection attempt","category":"Web Application Attack","severity":2}}'

logger --tcp --octet-count -n 100.80.61.14 -P 601 -t test-tcp "logger tcp"
logger --udp -n 100.80.61.14 -P 514 -t test-udp "logger udp rfc5424"
logger --udp --rfc3164 -n 100.80.61.14 -P 514 -t test-udp "logger udp rfc3164"
logger --tcp --octet-count -n 100.80.61.14 -P 601 -t snort "$SNORT"
logger --udp -n 100.80.61.14 -P 514 -t snort "$SNORT"
logger --tcp --octet-count -n 100.80.61.14 -P 601 -t suricata "$SURI"
logger --udp -n 100.80.61.14 -P 514 -t suricata "$SURI"
logger --tcp --octet-count -n 100.80.61.14 -P 601 -t apache-access '10.10.0.6 - - [09/Oct/2026:20:40:03 +0000] "GET /login.php?user=admin%27-- HTTP/1.1" 200 512 "-" "sqlmap/1.8"'
```

Résultat dans Elasticsearch (extrait) :

```
ids-alerts-2026.10.09  {"src_ip": "10.10.0.5", "dest_ip": "10.10.0.20", "dest_port": "22", "signature": "SSH brute force", "program": "snort", "priority": "1", "classification": "attempted-admin"}
ids-alerts-2026.10.09  {"src_ip": "10.10.0.6", "dest_ip": "10.10.0.20", "dest_port": "80", "signature": "SQL injection attempt", "program": "suricata", "priority": "2", "classification": "Web Application Attack"}
web-2026.10.09         {"src_ip": "10.10.0.6", "program": "apache-access", "http_status": "200", "user_agent": "sqlmap/1.8"}
syslog-2026.10.09      {"program": "test-tcp", "message": "logger tcp", "host": "siem-ids"}
syslog-2026.10.09      {"program": "test-udp", "message": "logger udp rfc3164", "host": "siem-ids"}
syslog-2026.10.09      {"program": "test-udp", "message": "logger udp rfc5424", "host": "siem-ids"}
```

Recherche par sous-réseau, possible grâce au type `ip` :

```bash
curl -s -u "elastic:$ELASTIC_PASSWORD" 'http://127.0.0.1:9200/ids-alerts-*/_count?q=src_ip:"10.10.0.0/24"'
# {"count":4,...}
```

En cas de problème, syslog-ng écrit ses erreurs dans `/var/log/syslog` :

```bash
grep 'syslog-ng\[' /var/log/syslog | tail
```
