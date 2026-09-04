#!/bin/sh
# Runs the three-agent Writ demo on localhost. Portable sh: macOS and NixOS.
# A (writ-demo) delegates to B (booking), B delegates to C (payment).
set -e
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
gosrc="$root/impl/go"
bin="$here/bin"
out="$here/out"
mkdir -p "$bin" "$out"
rm -f "$out"/*.json "$out"/store-*.json

( cd "$gosrc" && go build -o "$bin/writ-agent" ./cmd/writ-agent && go build -o "$bin/writ-demo" ./cmd/writ-demo )

SEED_A=0101010101010101010101010101010101010101010101010101010101010101
SEED_B=0202020202020202020202020202020202020202020202020202020202020202
SEED_C=0303030303030303030303030303030303030303030303030303030303030303
( cd "$gosrc" && go build -o "$bin/writ" ./cmd/writ )
DID_A=$("$bin/writ" keygen -seed $SEED_A)

"$bin/writ-agent" -role payment -seed $SEED_C -port 8082 -store "$out/store-C.json" -accept "$DID_A" > "$out/C.log" 2>&1 &
PC=$!
"$bin/writ-agent" -role booking -seed $SEED_B -port 8081 -store "$out/store-B.json" -accept "$DID_A" -downstream http://127.0.0.1:8082 > "$out/B.log" 2>&1 &
PB=$!
trap 'kill $PB $PC 2>/dev/null' EXIT INT TERM

i=0
until grep -q ready "$out/B.log" 2>/dev/null && grep -q ready "$out/C.log" 2>/dev/null; do
  i=$((i+1)); [ $i -gt 50 ] && { echo "agents did not start"; cat "$out/B.log" "$out/C.log"; exit 1; }
  sleep 0.2
done

"$bin/writ-demo" -seed $SEED_A -b http://127.0.0.1:8081 -c http://127.0.0.1:8082 -out "$out" | tee "$out/demo.log"
echo
echo "--- B log ---"; cat "$out/B.log"
echo "--- C log ---"; cat "$out/C.log"
