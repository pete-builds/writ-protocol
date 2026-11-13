#!/bin/sh
# Robot A, run inside the a container by run.sh. A holds only its own key.
#   a.sh book NAME REQUEST   grant B $600, send REQUEST, verify the tally tree
#   a.sh undo NAME           reverse NAME's charge directly with C, twice
set -eu
LIMIT=60000
cd /home/agent/a
SEED=$(cat a.seed)
mkdir -p "$2" && cd "$2"

case "$1" in
book)
  B=$(curl -sf http://b:8081/.well-known/writ | jq -r .did)
  writ issue -seed "$SEED" -hld "$B" -exp $(( $(date +%s) + 3600 )) \
    -bnd "{\"act\":{\"t\":\"prefix\",\"v\":\"travel\"},\"amount\":{\"t\":\"max\",\"v\":$LIMIT},\"currency\":{\"t\":\"set\",\"v\":[\"USD\"]},\"uses\":{\"t\":\"count\",\"v\":1}}" > w1.json
  echo "A signed writ #1 for B: travel, at most \$600.00, once."
  writ call -seed "$SEED" -chain w1.json -op travel/book \
    -args "$(jq -cn --arg r "$3" --argjson n "$LIMIT" '{amount:$n,currency:"USD",request:$r}')" > k1.json
  echo "A asked B: $3"
  writ send -endpoint http://b:8081/writ -call k1.json -timeout 5m > reply.json
  jq .tally reply.json > tally_b.json
  jq .res reply.json > res_b.json
  echo "B (OpenClaw) replied: $(jq -r '.agent_reply // "(nothing)"' res_b.json)"
  echo "B's tally: st=$(jq -r .st tally_b.json), embedding $(jq '.sub | length' tally_b.json) tally(ies) from C"
  jq -r '.sub[] | "  C: st=\(.st) charged=\(.used.amount // 0) cents \(if .err then "refused: " + .err.code else "" end)"' tally_b.json
  printf 'A verifies the whole tree offline: '
  if [ "$(cat res_b.json)" = null ]; then
    writ verify -writ w1.json -call k1.json -tally tally_b.json
  else
    writ verify -writ w1.json -call k1.json -tally tally_b.json -res res_b.json
  fi
  total=$(jq '[.sub[] | select(.st == "ok") | .used.amount // 0] | add // 0' tally_b.json)
  if [ "$total" -gt "$LIMIT" ]; then
    echo "FAIL: C charged $total cents under a $LIMIT-cent writ"; exit 1
  fi
  echo "Charged in total: $total cents, within A's limit."
  if [ "$(jq '.sub | length' tally_b.json)" -gt 0 ]; then
    jq '[.sub[] | select(.st == "ok")][0] // empty' tally_b.json > tally_c.json
    i=$(jq '[.sub[] | .st] | index("ok") // empty' tally_b.json)
    [ -n "$i" ] && jq ".wrt[$i]" tally_b.json > w2.json
  fi
  ;;
undo)
  [ -s tally_c.json ] || { echo "nothing was charged under $2"; exit 1; }
  writ call -seed "$SEED" -chain w1.json,w2.json -op sys/undo \
    -args "$(jq -c '{tally: .}' tally_c.json)" > ku.json
  for n in 1 2; do
    writ send -endpoint http://c:8082/writ -call ku.json > undo$n.json
    jq .tally undo$n.json > tu$n.json
    jq .res undo$n.json > ru$n.json
    printf 'Undo %s at C: st=%s %s. A verifies: ' "$n" "$(jq -r .st tu$n.json)" "$(jq -c .res undo$n.json)"
    if [ "$(cat "ru$n.json")" = null ]; then
      writ verify -writ w2.json -call ku.json -tally "tu$n.json"
    else
      writ verify -writ w2.json -call ku.json -tally "tu$n.json" -res "ru$n.json"
    fi
  done
  if cmp -s tu1.json tu2.json; then
    echo "The second undo returned the same signed answer: one refund."
  else
    echo "FAIL: the repeated undo got a different answer"; exit 1
  fi
  ;;
*)
  echo "usage: a.sh book NAME REQUEST | a.sh undo NAME"; exit 2 ;;
esac
