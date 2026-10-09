#!/usr/bin/env bash
# Installe la config syslog-ng collecteur. À lancer avec sudo depuis la racine du dépôt.
set -euo pipefail

cd "$(dirname "$0")/.."
SYSLOG_NG_PASSWORD=$(grep '^SYSLOG_NG_PASSWORD=' .env | cut -d= -f2-)

install -m 0644 configs/syslog-ng/collector.conf /etc/syslog-ng/conf.d/collector.conf

umask 077
cat > /etc/syslog-ng/es-credentials.conf <<CRED
@define es_user "syslog_ng"
@define es_password "${SYSLOG_NG_PASSWORD}"
CRED

syslog-ng --syntax-only
systemctl restart syslog-ng
systemctl --no-pager status syslog-ng | head -5
