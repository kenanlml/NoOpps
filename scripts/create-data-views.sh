#!/usr/bin/env bash
# Crée (ou remplace) les data views Kibana des trois familles d'index.
set -euo pipefail

cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

KIBANA=http://127.0.0.1:5601

# id fixe pour que le dashboard exporté référence toujours les mêmes data views
for dv in "ids-alerts:ids-alerts-*:Alertes IDS" "web:web-*:Logs web" "syslog:syslog-*:Syslog"; do
  IFS=: read -r id pattern name <<<"$dv"
  curl -sS -f -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
    -X POST "$KIBANA/api/data_views/data_view" \
    -d "{\"override\":true,\"data_view\":{\"id\":\"$id\",\"title\":\"$pattern\",\"name\":\"$name\",\"timeFieldName\":\"@timestamp\"}}" \
    -o /dev/null -w "$name ($pattern): %{http_code}\n"
done
