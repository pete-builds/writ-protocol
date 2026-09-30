#!/bin/sh
# Runs the three-agent Writ demo on localhost. Portable sh: macOS and NixOS.
# A (writ-demo) delegates to B (booking), B delegates to C (payment).
# WRIT_C=python runs C from the Python implementation instead of Go, so the
# two implementations talk to each other over the HTTP binding.
set -e
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
gosrc="$root/impl/go"
bin="$here/bin"
out="$here/out"
mkdir -p "$bin" "$out"
rm -f "$out"/*.json "$out"/store-*.json "$out"/*.log "$out"/audit-*.jsonl  # stale output must never pass a check
rm -rf "$out/store-C"

( cd "$gosrc" && go build -o "$bin/writ-agent" ./cmd/writ-agent && go build -o "$bin/writ-demo" ./cmd/writ-demo )

SEED_A=0101010101010101010101010101010101010101010101010101010101010101
SEED_B=0202020202020202020202020202020202020202020202020202020202020202
SEED_C=0303030303030303030303030303030303030303030303030303030303030303
( cd "$gosrc" && go build -o "$bin/writ" ./cmd/writ )
DID_A=$("$bin/writ" keygen -seed $SEED_A)

if [ "${WRIT_C:-go}" = python ]; then
  ( cd "$root/impl/python" && exec python3 -m writ.cli serve --role payment --seed $SEED_C --port 8082 --store "$out/store-C" --accept "$DID_A" --audit "$out/audit-C.jsonl" ) > "$out/C.log" 2>&1 &
else
  "$bin/writ-agent" -role payment -seed $SEED_C -port 8082 -store "$out/store-C.json" -audit "$out/audit-C.jsonl" -accept "$DID_A" > "$out/C.log" 2>&1 &
fi
PC=$!
"$bin/writ-agent" -role booking -seed $SEED_B -port 8081 -store "$out/store-B.json" -audit "$out/audit-B.jsonl" -accept "$DID_A" -downstream http://127.0.0.1:8082 > "$out/B.log" 2>&1 &
PB=$!
trap 'kill $PB $PC 2>/dev/null' EXIT INT TERM

i=0
until grep -q ready "$out/B.log" 2>/dev/null && grep -q ready "$out/C.log" 2>/dev/null; do
  i=$((i+1)); [ $i -gt 50 ] && { echo "agents did not start"; cat "$out/B.log" "$out/C.log"; exit 1; }
  sleep 0.2
done

# Run A without a pipe so its exit status survives (POSIX sh has no pipefail).
status=0
"$bin/writ-demo" -seed $SEED_A -b http://127.0.0.1:8081 -c http://127.0.0.1:8082 -out "$out" > "$out/demo.log" 2>&1 || status=$?
# Each agent keeps an audit record (spec 9.3).
for a in B C; do
  [ -s "$out/audit-$a.jsonl" ] || { echo "AUDIT FAILED: $a wrote no audit record" >> "$out/demo.log"; status=1; }
done
grep -q '"outcome":"ok"' "$out/audit-C.jsonl" 2>/dev/null || { echo "AUDIT FAILED: C recorded no completed call" >> "$out/demo.log"; status=1; }
# B answers the demo's seven rejected attempts, each a signed refusal.
refused=$(grep -c '"outcome":"failed"' "$out/audit-B.jsonl" 2>/dev/null || true)
[ "${refused:-0}" -ge 7 ] || { echo "AUDIT FAILED: B recorded ${refused:-0} refusals, want at least 7" >> "$out/demo.log"; status=1; }
cat "$out/demo.log"
echo
echo "--- B log ---"; cat "$out/B.log"
echo "--- C log ---"; cat "$out/C.log"
exit $status
