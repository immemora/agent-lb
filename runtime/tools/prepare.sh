#!/bin/sh
# One-shot, idempotent preparation of bind-mounted state (runs as root, no network).
# - Copies the source Tailscale state once (never touches the source; mounted :ro).
# - Creates the state dirs with the right owners and modes.
set -eu

APP_UID=1000
APP_GID=1000

log() { echo "[prepare] $*"; }

mkdir -p /status/tailscale /status/agent-lb /status/postgres /status/retention-archive
if [ ! -s /status/tailscale/tailscaled.state ]; then
    if [ ! -s /source-tailscale/tailscaled.state ]; then
        echo "[prepare] FAILED: no tailscale state here or in the source" >&2
        exit 1
    fi
    cp -a /source-tailscale/. /status/tailscale/
    log "copied the source tailscale state (identity reused)"
fi
chmod 700 /status/tailscale

chown "$APP_UID:$APP_GID" /status/agent-lb /status/retention-archive
chmod 700 /status/agent-lb
chmod 750 /status/retention-archive

# Token vault: outside both repos; owned by the app user, 0700.
mkdir -p /vault
chown "$APP_UID:$APP_GID" /vault
chmod 700 /vault

log "state dirs ready"
