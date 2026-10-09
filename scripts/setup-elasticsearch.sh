#!/usr/bin/env bash
# Crée le rôle et l'utilisateur syslog-ng, puis le template d'index.
set -euo pipefail

cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

ES=http://127.0.0.1:9200
CFG=configs/elasticsearch

es() {
  curl -sS -f -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' "$@"
  echo
}

es -X PUT "$ES/_security/role/syslog_ng_writer" --data-binary "@$CFG/role-syslog-ng.json"
es -X PUT "$ES/_security/user/syslog_ng" \
  -d "{\"password\":\"${SYSLOG_NG_PASSWORD}\",\"roles\":[\"syslog_ng_writer\"],\"full_name\":\"syslog-ng collecteur\"}"
es -X PUT "$ES/_index_template/siem" --data-binary "@$CFG/index-template.json"

# Index vides : sans index correspondant, les data views n'ont aucun champ et le
# dashboard affiche "Field @timestamp was not found" tant qu'aucun log n'est arrivé.
for idx in ids-alerts-init web-init syslog-init; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -u "elastic:${ELASTIC_PASSWORD}" -I "$ES/$idx")
  if [ "$code" = 404 ]; then
    es -X PUT "$ES/$idx"
  else
    echo "$idx existe déjà"
  fi
done
