#!/bin/sh
# Daily request-log retention (30 days) using agent-lb's own Postgres-only tool.
# Applies only when the operator's standing approval record exists and is
# non-empty; otherwise it logs the refusal and runs a dry-run for visibility.
# A failed run never stops the loop.
set -u

APPROVAL=/approval/retention-approval.md
ARCHIVE=/archive
DAYS=30
INTERVAL_SECONDS=86400

log() { echo "[retention] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

while true; do
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$ARCHIVE/receipts"
    if [ -s "$APPROVAL" ]; then
        log "applying retention (--days $DAYS)"
        if agent-lb retention run --apply --days "$DAYS" --archive-dir "$ARCHIVE" \
            --approval "$APPROVAL" --receipt "$ARCHIVE/receipts/$stamp.json"; then
            log "done; receipt receipts/$stamp.json"
        else
            log "run failed (exit $?); retrying next cycle"
        fi
    else
        log "no approval record at $APPROVAL; refusing --apply, dry-run only"
        agent-lb retention run --dry-run --days "$DAYS" --archive-dir "$ARCHIVE" \
            || log "dry-run failed (exit $?)"
    fi
    sleep "$INTERVAL_SECONDS"
done
