# Installation et configuration de Snort 3

Snort 3 tourne sur la VM victime (serveur web). Il analyse le trafic du réseau du lab, écrit ses alertes en JSON, et syslog-ng les envoie au collecteur de la VM `siem-ids`, qui les range dans l'index `ids-alerts-*` d'Elasticsearch.

```
Kali (192.168.56.x) ──attaques──▶ victime enp0s8 (192.168.56.20)
                                    │ Snort 3 → /var/log/snort/alert_json.txt
                                    │ syslog-ng client (client-ids.conf)
                                    ▼ TCP, IP publique du SIEM, port 6001
                                  box → NAT VMware → siem-ids:601 (collecteur) → Elasticsearch → Kibana
```

## État d'avancement

| Étape | État |
|-------|------|
| Compilation et installation de Snort 3 et libdaq | fait |
| Règles communautaires | fait |
| Test de détection (règle ping, Snort au premier plan) | fait |
| syslog-ng client sur la victime, envoi vers le SIEM | fait |
| Ouverture du port 6001 vers le collecteur | fait (port joignable) |
| `local.lua` et règles des 5 scénarios déployés sur la victime | en cours |
| Service `snort3` corrigé (interface, `--tweaks local`) | en cours |
| Alertes visibles dans Kibana (test de bout en bout) | à faire |
| Test et réglage des seuils pour chaque scénario | à faire |

## 1. Choix

**Snort 3 compilé depuis les sources.** `apt install snort` installe Snort 2.9, en fin de vie et sans sortie `alert_json`. Le collecteur attend le JSON de Snort 3 (voir [02-syslog-ng.md](02-syslog-ng.md)).

**Snort sur la victime.** Snort écoute directement l'interface de la VM attaquée : il voit toutes les attaques qui la visent, sans mode promiscuous ni VM supplémentaire. En contrepartie, il ne protège que cet hôte et partage ses ressources avec la cible (voir [Limites](#8-limites-et-améliorations)). Un capteur dédié sur un port miroir, ou Snort en coupure sur un routeur (mode IPS), serait plus réaliste.

**Réseau de la victime (VirtualBox).**

| Interface | Adresse         | Rôle                                                          |
|-----------|-----------------|---------------------------------------------------------------|
| `enp0s3`  | `10.0.2.15`     | NAT VirtualBox : accès internet, envoi des logs vers le SIEM  |
| `enp0s8`  | `192.168.56.20` | réseau host-only du lab, partagé avec Kali : **écouté par Snort** |

Les attaques restent dans le réseau host-only : la victime, volontairement vulnérable, n'est pas exposée sur internet.

## 2. Installation

VM victime sous Ubuntu 24.04. Le script `scripts/install-snort.sh` fait toute l'installation :

```bash
sudo ./scripts/install-snort.sh
```

| Étape | Contenu |
|-------|---------|
| 1. Paquets | outils de compilation et bibliothèques (`libpcap-dev`, `libpcre2-dev`, `libdumbnet-dev`, `libhwloc-dev`, `libluajit-5.1-dev`, `libfl-dev`, `libhyperscan-dev`…), `ethtool` |
| 2. libdaq `v3.0.27` | couche de capture des paquets, compilée dans `/usr/local/src/libdaq` |
| 3. Snort `3.12.2.0` | compilé dans `/usr/local/src/snort3` (10 à 30 min), installé dans `/usr/local` |
| 4. Utilisateur | utilisateur système `snort`, dossier `/var/log/snort` qui lui appartient |
| 5. Règles | règles communautaires Snort 3 dans `/usr/local/etc/rules/snort3-community.rules` |

Vérification :

```bash
snort -V                                         # Version 3.12.2.0
snort -c /usr/local/etc/snort/snort.lua -T       # Snort successfully validated the configuration
```

Le script est fait pour une VM neuve : relancé, il s'arrête au `git clone` de libdaq, le dossier existant déjà.

## 3. Configuration

Le `snort.lua` d'origine n'est pas modifié. Les réglages du projet sont dans `/usr/local/etc/snort/local.lua`, chargé à la fin de `snort.lua` par l'option `--tweaks local`.

```lua
-- Réseau protégé (la victime) et réseau externe (tout le reste)
default_variables.nets.HOME_NET = '192.168.56.20'
default_variables.nets.EXTERNAL_NET = '!192.168.56.20'

ips =
{
    -- alertes des inspecteurs, dont port_scan
    enable_builtin_rules = true,
    variables = default_variables,
    rules = [[
        include $RULE_PATH/snort3-community.rules
        include $RULE_PATH/local.rules
    ]],
}

-- une seule alerte par période pour les règles à seuil (scan, SSH, flood)
event_filter =
{
    { gid = 1, sid = 1000001, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 1000003, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 1000012, type = 'limit', track = 'by_dst', count = 1, seconds = 5 },
}

-- sortie JSON lue par syslog-ng
alert_json =
{
    file = true,
    limit = 100,
    fields = 'timestamp proto src_addr src_port dst_addr dst_port gid sid rev msg class priority action',
}
```

- **`HOME_NET`.** `snort_defaults.lua` recopie `HOME_NET` (`'any'`) dans `default_variables` dès son chargement. Redéfinir `HOME_NET` dans les tweaks ne suffit pas : c'est `default_variables.nets` qu'il faut modifier.
- **`enable_builtin_rules`.** Sans cette option, l'inspecteur `port_scan` (déjà actif dans `snort.lua`) détecte les scans mais n'émet aucune alerte (gid 122).
- **`alert_json`.** Les champs par défaut ne contiennent ni les adresses IP ni le message de la règle. La liste `fields` correspond à ce que lit le collecteur (`src_addr`, `dst_addr`, `msg`, `class`, `priority`…). Le fichier tourne à 100 Mo.
- **`event_filter`.** Une règle à seuil (`detection_filter`) alerte sur chaque paquet au-delà du seuil : un scan de 1000 ports donnerait près de 1000 alertes. Le filtre n'en garde qu'une par attaquant et par minute (une toutes les 5 s pour le flood).

Vérification :

```bash
sudo snort -c /usr/local/etc/snort/snort.lua --tweaks local -T
```

## 4. Règles locales

Fichier `/usr/local/etc/rules/local.rules`. SID à partir de 1000001, `rev` incrémenté à chaque modification.

Chaque `msg` commence par `LOCAL` et contient le mot utilisé par le filtre KQL du panneau du scénario dans le dashboard (voir [visualisation.md](../visualisation.md)), et aucun mot d'un autre scénario : par exemple, un message SQL ne doit pas contenir « scan », exclu par le panneau SQL / XSS.

| SID | Scénario | Détection | Message |
|-----|----------|-----------|---------|
| 1000001 | Scan de ports | plus de 20 SYN en 3 s depuis la même source | `LOCAL SCAN SYN scan de ports` |
| 1000002 | Scan de services | `Nmap` dans le User-Agent HTTP (scripts NSE) | `LOCAL SCAN nmap NSE sur le serveur web` |
| 1000003 | Brute-force SSH | plus de 5 SYN vers le port 22 en 60 s depuis la même source | `LOCAL SSH brute force possible` |
| 1000004 | Injection SQL | `union` puis `select` dans l'URI | `LOCAL SQL injection UNION SELECT` |
| 1000005 | Injection SQL | `' or 1=1` dans l'URI (pcre) | `LOCAL SQL injection OR 1=1` |
| 1000006 | Injection SQL | `sqlmap` dans le User-Agent | `LOCAL SQL injection outil sqlmap` |
| 1000007 | XSS reflected | `<script` dans l'URI | `LOCAL XSS balise script dans l'URI` |
| 1000008 | XSS stored | `<script` dans le corps de la requête | `LOCAL XSS balise script dans le formulaire` |
| 1000009 | Exploit HTTP | `.%2e/` dans l'URI brute (CVE-2021-41773) | `LOCAL EXPLOIT path traversal CVE-2021-41773` |
| 1000010 | Exploit HTTP | `/etc/passwd` dans l'URI | `LOCAL EXPLOIT lecture de /etc/passwd` |
| 1000011 | Exploit HTTP | `() {` dans un en-tête (Shellshock) | `LOCAL EXPLOIT Shellshock CVE-2014-6271` |
| 1000012 | Flood ICMP | plus de 100 echo request par seconde vers la même cible | `LOCAL FLOOD ICMP ping flood` |

Exemple commenté (dans le fichier, une règle tient sur une ligne) :

```
alert tcp any any -> $HOME_NET 22 (
    msg:"LOCAL SSH brute force possible";
    flags:S;                                              # ouvertures de connexion uniquement
    detection_filter:track by_src, count 5, seconds 60;   # au-delà de 5 connexions en 60 s par source
    classtype:attempted-admin;                            # catégorie, qui fixe la priorité (1)
    sid:1000003; rev:1;
)
```

- **URI normalisée ou brute.** `http_uri` est décodée et normalisée par Snort (`%20` → espace, `/./` et `/../` simplifiés) : c'est ce qu'on veut pour `union select`. Pour le path traversal, la normalisation ferait disparaître `.%2e/`, d'où `http_raw_uri`.
- **SSH chiffré.** Le contenu des tentatives est invisible pour Snort : seul le nombre de connexions est détectable. Les échecs eux-mêmes sont dans `auth.log` (envoyé par `client-web.conf`).
- **Seuils.** Les valeurs du tableau sont des valeurs de départ, à ajuster pendant les tests (valeurs testées et retenues à noter dans les fiches des scénarios).

Méthode utilisée pour écrire et tester une règle :

1. Capturer l'attaque sur la victime : `sudo tcpdump -i enp0s8 -w /tmp/attaque.pcap host <IP Kali>`.
2. Repérer ce qui la distingue du trafic normal (Wireshark ou `tcpdump -A -r`).
3. Écrire la règle, vérifier la syntaxe avec `-T`.
4. La rejouer sur la capture, sans relancer l'attaque :
   ```bash
   sudo snort -c /usr/local/etc/snort/snort.lua --tweaks local -r /tmp/attaque.pcap -A alert_fast -q -k none
   ```
5. Rejouer de la même façon une capture de trafic normal : la règle ne doit pas se déclencher.
6. Tester en réel depuis Kali et vérifier le panneau du dashboard.

## 5. Service systemd

`/etc/systemd/system/snort3.service` :

```ini
[Unit]
Description=Snort3 NIDS Daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=-/usr/sbin/ethtool -K enp0s8 gro off lro off
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua --tweaks local -i enp0s8 -A alert_json -l /var/log/snort -k none -u snort -g snort -q
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now snort3
sudo systemctl restart snort3        # après chaque modification des règles
```

- **GRO/LRO** regroupent les paquets avant qu'ils n'arrivent à Snort, qui rate alors des détections. Le `-` devant `ethtool` ignore l'échec si la carte virtuelle ne gère pas l'une des options.
- **`-k none`** : sans cette option, Snort ignore les paquets dont la somme de contrôle est calculée par la carte réseau, fréquents sur les paquets émis par la VM elle-même.
- **`-u snort -g snort`** : Snort ne tourne pas en root après l'ouverture de l'interface.
- **Pas de `-D`.** Avec `Type=simple`, systemd considère le service terminé dès que le processus lancé se met en arrière-plan, et arrête Snort.

## 6. Envoi des alertes au SIEM

syslog-ng client sur la victime (`syslog-ng-core`, qui remplace `rsyslog`). Fichier `/etc/syslog-ng/conf.d/client-ids.conf`, d'après [configs/syslog-ng/client-ids.conf](../../configs/syslog-ng/client-ids.conf) :

```
destination d_collector_ids {
    syslog("<IP publique du SIEM>" transport("tcp") port(6001)
        persist-name("collector-ids")
        disk-buffer(reliable(no) capacity-bytes(268435456) dir("/var/lib/syslog-ng"))
    );
};

source s_snort {
    file("/var/log/snort/alert_json.txt" program-override("snort") flags(no-parse));
};

log { source(s_snort); destination(d_collector_ids); };
```

```bash
sudo syslog-ng --syntax-only && sudo systemctl restart syslog-ng
sudo systemctl enable syslog-ng
```

- **Pas de Tailscale.** La victime envoie ses logs à l'IP publique du SIEM. Le port externe 6001 est redirigé par la box puis par le NAT VMware vers le port 601 du collecteur (`172.16.24.110:601`), ce qui évite de modifier le collecteur. À confirmer par le test de bout en bout (`tcpdump -ni ens33 'tcp port 601 or tcp port 6001'` sur `siem-ids`).
- **`program-override("snort")`** marque les lignes pour que le collecteur les route vers `ids-alerts-*` ; `flags(no-parse)` envoie la ligne JSON telle quelle.
- **Disk-buffer** de 256 Mo : les alertes sont gardées si le SIEM est injoignable.

Vérification :

```bash
nc -vz <IP publique du SIEM> 6001                # succeeded
ss -tn dst <IP publique du SIEM>:6001            # une connexion ESTAB
sudo syslog-ng-ctl stats | grep collector        # compteur processed qui augmente
```

Puis, dans Kibana : Discover, data view « Alertes IDS », champs `src_ip`, `dest_ip`, `signature`, `priority` renseignés.

## 7. Problèmes rencontrés

| Problème | Cause | Solution |
|----------|-------|----------|
| `install-snort.sh` ne fait rien, sans message | le script n'était pas encore poussé sur le dépôt, la copie sur la victime n'était pas à jour | recopier le script, vérifier son contenu avec `wc -l` et `head` |
| `duplicate destination definition` au `--syntax-only` | le bloc d'envoi avait été collé à la fin de `syslog-ng.conf` et aussi dans `conf.d/client-ids.conf` | supprimer le bloc de `syslog-ng.conf` : les ajouts vont uniquement dans `conf.d/` |
| Service `snort3` actif mais aucune alerte utile | unité avec `-D` (arrière-plan sous `Type=simple`), interface `eth0` inexistante, sans `--tweaks local` | unité réécrite (section 5) |
| GRO/LRO toujours actifs | service `ethtool` écrit pour `ens3`, alors que l'interface du lab est `enp0s8` | désactivation dans `ExecStartPre` du service Snort, sur `enp0s8` |
| syslog-ng du SIEM non relancé au démarrage | service `disabled` sur `siem-ids` | `sudo systemctl enable syslog-ng` |

## 8. Limites et améliorations

**Limites**

- Snort tourne sur la machine attaquée : il ne protège qu'elle, et sous un flood il partage le CPU avec la cible et peut perdre des paquets.
- Détection par signatures et par seuils : une attaque modifiée, ou lente (sous les seuils), passe inaperçue.
- Trafic chiffré : en HTTPS, Snort ne voit pas le contenu des requêtes ; en SSH, seul le volume de connexions est visible.
- Logs envoyés en clair sur internet (syslog TCP sans TLS) vers un port ouvert ; un filtrage par IP source ne couvre que l'IP publique de la box, partagée par tout le réseau local de la victime.
- Mode IDS seulement : Snort alerte mais ne bloque rien.

**Améliorations possibles**

- Capteur Snort dédié sur un port miroir, ou en coupure sur un routeur pour passer en mode IPS (blocage).
- syslog en TLS (port 6514, certificats) ou passage par un VPN pour l'envoi des logs.
- PulledPork3 pour mettre à jour les règles automatiquement et gérer les faux positifs (`disablesid.conf`).
- Suricata en parallèle de Snort pour comparer les deux moteurs sur les mêmes attaques.
