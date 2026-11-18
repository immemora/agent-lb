#!/bin/sh
# Operator acceptance checks that need secrets (run from a tailnet machine).
#   API_KEY=sk-clb-...  sh tools/acceptance.sh            key + streaming checks
#   sh tools/acceptance.sh --password                      dashboard login (prompted)
# Prints status codes and timings only; never echoes the key or password.
set -u
HOSTS="${HOSTS:-tailscale-codex-lb tailscale-codex-lb.tail4accf3.ts.net 100.107.36.53}"
MODEL="${MODEL:-gpt-5.4-mini}"

if [ "${1:-}" = "--password" ]; then
    printf "dashboard password: "; stty -echo; read -r PW; stty echo; echo
    body=$(PW="$PW" python3 -I -c 'import json,os; print(json.dumps({"password": os.environ["PW"]}))')
    for host in $HOSTS; do for port in 2455 80; do
        code=$(printf '%s' "$body" | curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -H 'content-type: application/json' --data-binary @- "http://$host:$port/api/dashboard-auth/password/login")
        echo "login $host:$port -> $code (expect 200)"
    done; done
    exit 0
fi

: "${API_KEY:?set API_KEY=sk-clb-...}"
for host in $HOSTS; do for port in 2455 80; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -H "Authorization: Bearer $API_KEY" "http://$host:$port/v1/models")
    echo "models $host:$port -> $code (expect 200)"
done; done

host=${HOSTS%% *}
echo "SSE through :80 (each line: seconds since start, event type); expect events spread over time:"
start=$(date +%s.%N)
curl -sN --max-time 300 -H "Authorization: Bearer $API_KEY" -H 'content-type: application/json' \
    -d "{\"model\":\"$MODEL\",\"stream\":true,\"input\":\"Count from 1 to 40, one number per line.\"}" \
    "http://$host:80/v1/responses" \
    | while IFS= read -r line; do
        case "$line" in event:*) awk -v s="$start" -v n="$(date +%s.%N)" -v e="${line#event: }" 'BEGIN{printf "%6.2fs %s\n", n-s, e}';; esac
      done | awk 'NR<=3 || /completed|error|failed/'
