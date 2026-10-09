# Visualisation

## Data views

Voir [installation/03-elk.md](installation/03-elk.md#4-kibana--data-views-et-dashboard). Le dashboard utilise la data view `ids-alerts` (`ids-alerts-*`).

## Dashboard « SIEM - Détection d'intrusions »

Export : `kibana/dashboard.ndjson` (dashboard, visualisations Lens, recherche enregistrée et data view `ids-alerts`). Import :

```bash
./scripts/import-dashboard.sh
```

Le dashboard s'ouvre sur les dernières 24 h et se rafraîchit toutes les 30 secondes.

| Panneau                         | Type                     | Contenu                                         |
|---------------------------------|--------------------------|-------------------------------------------------|
| Alertes dans le temps           | barres empilées          | nombre d'alertes par intervalle, par priorité   |
| Répartition par priorité        | anneau                   | part des priorités 1, 2 et 3                    |
| Top 10 des IP sources           | barres horizontales      | `src_ip` les plus fréquentes                    |
| Alertes par signature (top 10)  | barres horizontales      | `signature` les plus fréquentes                 |
| Scénario : ... (5 panneaux)     | barres empilées          | alertes du scénario dans le temps, par `src_ip` |
| Derniers événements IDS         | recherche enregistrée    | tableau trié par date décroissante              |

Priorités : 1 en rouge, 2 en jaune, 3 en vert (palette `status`). Côté Suricata, la priorité vient de `alert.severity`, côté Snort de `priority`. Dans les deux cas, 1 est la plus grave.

### Filtres des panneaux par scénario

Chaque panneau de scénario est une visualisation Lens filtrée par une requête KQL, rappelée dans sa description (icône d'information à côté du titre). Les filtres reposent sur les mots des signatures (`signature.text`, champ analysé) et sur quelques champs normalisés. Ils devront être ajustés quand les règles réelles de l'IDS seront connues, en particulier si l'équipe écrit ses propres règles avec des messages en français.

| Scénario               | Requête KQL |
|------------------------|-------------|
| Scan de ports          | `(signature.text : (scan or nmap) or classification : ("attempted-recon" or "Detection of a Network Scan")) and not dest_port : 22` |
| Brute-force SSH        | `dest_port : 22 or signature.text : ssh` |
| Injection SQL / XSS    | `signature.text : (sql or xss or "cross site scripting" or injection) and not signature.text : scan` |
| Exploit HTTP           | `signature.text : (exploit or cve or traversal or passwd or rce or shellshock or "remote code execution")` |
| Flood ICMP             | `proto : ICMP` |

Le `not signature.text : scan` du panneau SQL / XSS écarte les signatures de scan qui contiennent « SQL » (`ET SCAN Suspicious inbound to mySQL port 3306`, par exemple).

Pour modifier un filtre : Edit sur le dashboard, puis Edit visualization sur le panneau. Exporter ensuite à nouveau le dashboard (Stack Management > Saved objects > Export, avec les objets liés) vers `kibana/dashboard.ndjson`.

## Données de démo

Le dashboard a été construit sur des données générées par `scripts/demo-data.py`, qui produit 24 h de trafic dans des index `demo-ids-alerts-*`, `demo-web-*` et `demo-syslog-*`. Les documents ont la même forme que ceux du collecteur (alertes Suricata normalisées avec `raw`, logs Apache parsés, syslog) :

| Scénario              | Attaquant(s)                       | Contenu                                                            |
|-----------------------|------------------------------------|--------------------------------------------------------------------|
| Scan de ports         | 203.0.113.45 (nuit), 192.168.56.10 | signatures ET SCAN, requêtes web avec l'user-agent Nmap            |
| Brute-force SSH       | 198.51.100.23, 203.0.113.150       | `Failed password` dans syslog, ET SCAN Potential SSH Scan, règle locale |
| Injection SQL / XSS   | 192.168.56.10 (sqlmap), 203.0.113.77 | requêtes encodées, erreurs PHP, signatures ET WEB_SERVER         |
| Exploit HTTP          | 203.0.113.99, 198.51.100.66        | CVE-2021-41773/42013, Shellshock, PHPUnit, ThinkPHP                |
| Flood ICMP            | 198.51.100.200, 198.51.100.201     | alerte locale à seuil (une par seconde), pings                     |

S'y ajoute un bruit de fond : navigation web depuis le LAN, pings de supervision toutes les 5 minutes, CRON, connexions SSH d'administration. Les adresses externes sont dans les plages réservées à la documentation (RFC 5737).

```bash
./scripts/demo-data.py load     # (re)crée les index demo-* et le dashboard de démo
./scripts/demo-data.py delete   # supprime les index et les objets Kibana de démo
```

`load` importe aussi un dashboard « SIEM - Démo (données fictives) », copie de `kibana/dashboard.ndjson` construite au moment du chargement : les id sont préfixés par `demo-` et la data view `demo-ids-alerts` pointe vers `demo-ids-alerts-*`. Le dashboard réel et ses data views ne sont pas modifiés. Comme la copie est faite à partir de l'export, une modification du dashboard réel se retrouve dans la démo au `load` suivant.

Les données sont générées sur les 24 h précédant le `load`. Il faut le relancer pour retrouver un dashboard rempli sur la période « Last 24 hours ».

Le compte `equipe` n'a pas accès aux index `demo-*` : le dashboard de démo s'affiche vide avec ce compte.

## Captures

<!-- Captures dans screenshots/, à faire avec les vraies alertes des scénarios -->

## Visualisations par scénario

<!-- Une section par scénario : requête KQL, visualisation, capture -->
