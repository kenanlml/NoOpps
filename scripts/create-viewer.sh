#!/usr/bin/env bash
# Crée le rôle siem_viewer et l'utilisateur Kibana en lecture seule de l'équipe.
set -euo pipefail

cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

# Rôle créé via l'API Kibana : l'API Elasticsearch ne gère pas les privilèges par fonctionnalité Kibana
curl -sS -f -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X PUT "http://127.0.0.1:5601/api/security/role/siem_viewer" \
  --data-binary @configs/elasticsearch/role-siem-viewer.json \
  -o /dev/null -w "rôle siem_viewer : %{http_code}\n"

curl -sS -f -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' \
  -X PUT "http://127.0.0.1:9200/_security/user/${KIBANA_VIEWER_USER}" \
  -d "{\"password\":\"${KIBANA_VIEWER_PASSWORD}\",\"roles\":[\"siem_viewer\"],\"full_name\":\"Équipe (lecture seule)\"}"
echo
