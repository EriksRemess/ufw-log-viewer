#!/usr/bin/env sh
set -eu

URL="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
OUT="data/service-names-port-numbers.csv"

mkdir -p "$(dirname "$OUT")"
curl -fsSL "$URL" -o "$OUT"
wc -l "$OUT"
