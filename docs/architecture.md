# Architecture

```mermaid
flowchart LR
    subgraph IDS["VM IDS"]
        snort["Snort 3 / Suricata<br/>alert_json.txt / eve.json"]
        sngids["syslog-ng client<br/>client-ids.conf"]
        snort --> sngids
    end

    subgraph WEB["VM serveur web (victime)"]
        apache["Apache<br/>access.log, error.log"]
        auth["auth.log"]
        sngweb["syslog-ng client<br/>client-web.conf"]
        apache --> sngweb
        auth --> sngweb
    end

    subgraph SIEM["VM siem-ids (VMware, Tailscale 100.80.61.14)"]
        coll["syslog-ng collecteur<br/>601/tcp, 514/udp"]
        es[("Elasticsearch 8<br/>127.0.0.1:9200")]
        kib["Kibana<br/>127.0.0.1:5601"]
        coll -- "elasticsearch-http()<br/>utilisateur syslog_ng" --> es
        kib --> es
    end

    sngids -- "RFC 5424, 601/tcp<br/>via Tailscale" --> coll
    sngweb -- "RFC 5424, 601/tcp<br/>via Tailscale" --> coll
    poste["Poste de travail"] -- "tunnel SSH<br/>localhost:5601" --> kib
```

## Flux

| Source            | Transport               | Destination            | Index                  |
|-------------------|-------------------------|------------------------|------------------------|
| alertes Snort 3 / Suricata | syslog TCP 601 (Tailscale) | collecteur syslog-ng | `ids-alerts-%Y.%m.%d` |
| Apache access/error | syslog TCP 601 (Tailscale) | collecteur syslog-ng | `web-%Y.%m.%d`       |
| auth.log, autres  | syslog TCP 601 ou UDP 514 | collecteur syslog-ng | `syslog-%Y.%m.%d`      |
| collecteur        | HTTP `_bulk` sur 127.0.0.1:9200 | Elasticsearch | |

## Réseau

- La VM `siem-ids` tourne sous VMware (interface `ens33`, `172.16.24.110`) et a Tailscale installé directement. Les clients envoient à son IP Tailscale `100.80.61.14`, sans redirection de ports.
- Seuls 22/tcp (SSH), 601/tcp et 514/udp (syslog) écoutent sur les interfaces réseau.
- Elasticsearch et Kibana ne sont publiés que sur `127.0.0.1`. Kibana s'utilise depuis un tunnel SSH.
- Aucun pare-feu n'est configuré pour l'instant.
