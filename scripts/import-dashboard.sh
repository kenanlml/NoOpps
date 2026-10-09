#!/usr/bin/env bash
# Importe kibana/dashboard.ndjson dans Kibana (écrase les objets existants).
set -euo pipefail

cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

FILE=${1:-kibana/dashboard.ndjson}
[ -f "$FILE" ] || { echo "fichier introuvable : $FILE" >&2; exit 1; }

curl -sS -f -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' \
  -X POST "http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true" \
  --form file=@"$FILE"
echo
