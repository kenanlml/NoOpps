#!/usr/bin/env bash
# Compile et installe libdaq et Snort 3 sur la VM victime (Ubuntu 24.04), puis les
# règles communautaires. À lancer avec sudo depuis la racine du dépôt.
# Versions modifiables : sudo SNORT_VERSION=3.12.2.0 ./scripts/install-snort.sh
set -euo pipefail

cd "$(dirname "$0")/.."
REPO=$(pwd)

LIBDAQ_VERSION=${LIBDAQ_VERSION:-v3.0.27}
SNORT_VERSION=${SNORT_VERSION:-3.12.2.0}
PREFIX=/usr/local
SRC=/usr/local/src
RULES=$PREFIX/etc/rules

[ "$(id -u)" -eq 0 ] || { echo "à lancer avec sudo" >&2; exit 1; }

# libfl-dev fournit FlexLexer.h, utilisé par le normaliseur JavaScript de Snort
apt-get update
apt-get install -y build-essential cmake pkg-config git curl ca-certificates \
  autoconf automake libtool flex libfl-dev bison \
  libpcap-dev libpcre2-dev libdumbnet-dev libhwloc-dev libluajit-5.1-dev \
  zlib1g-dev liblzma-dev libssl-dev uuid-dev ethtool
# Hyperscan accélère la recherche de motifs, paquet disponible seulement en x86_64
if [ "$(uname -m)" = x86_64 ]; then
  apt-get install -y libhyperscan-dev
fi

mkdir -p "$SRC"

# Clone (ou réutilise) le dépôt au tag demandé
fetch() {
  local repo=$1 tag=$2 dir=$3
  [ -d "$dir" ] || git clone --depth 1 --branch "$tag" "https://github.com/snort3/$repo.git" "$dir"
}

if ! [ -f "$PREFIX/lib/libdaq.so" ]; then
  fetch libdaq "$LIBDAQ_VERSION" "$SRC/libdaq-$LIBDAQ_VERSION"
  cd "$SRC/libdaq-$LIBDAQ_VERSION"
  ./bootstrap
  ./configure --prefix="$PREFIX"
  make -j"$(nproc)"
  make install
  ldconfig
fi

if ! "$PREFIX/bin/snort" -V 2>/dev/null | grep -q "Version ${SNORT_VERSION}"; then
  fetch snort3 "$SNORT_VERSION" "$SRC/snort3-$SNORT_VERSION"
  cd "$SRC/snort3-$SNORT_VERSION"
  ./configure_cmake.sh --prefix="$PREFIX"
  # Compilation longue (10 à 30 min) et gourmande en mémoire : nproc limité à 2 si moins de 4 Go
  jobs=$(nproc)
  [ "$(awk '/MemTotal/ {print int($2/1048576)}' /proc/meminfo)" -ge 4 ] || jobs=$(( jobs < 2 ? jobs : 2 ))
  make -C build -j"$jobs"
  make -C build install
  ldconfig
fi

# Snort tourne sous un utilisateur dédié ; syslog-ng (root) lit ses alertes
id snort &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin snort
install -d -o snort -g snort -m 0755 /var/log/snort

# Règles communautaires Snort 3, plus les règles locales du dépôt si elles existent
install -d -m 0755 "$RULES"
curl -sSfL https://www.snort.org/downloads/community/snort3-community-rules.tar.gz \
  | tar -xz -C "$SRC"
install -m 0644 "$SRC/snort3-community-rules/snort3-community.rules" "$RULES/"
if [ -f "$REPO/configs/snort/local.rules" ]; then
  install -m 0644 "$REPO/configs/snort/local.rules" "$RULES/local.rules"
fi

"$PREFIX/bin/snort" -V
