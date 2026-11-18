#!/bin/sh
# Create the deployment's secret env files once (idempotent; never overwrites).
#   .env            POSTGRES_PASSWORD (generated), used by compose interpolation
#   .env.tailscale  TS_AUTHKEY, copied from the codex-lb-hardened source
# Never prints a secret.
set -eu
cd "$(dirname "$0")"
umask 077

SOURCE_ENV=../../codex-lb-hardened/.env.local

if [ ! -s .env ]; then
    printf 'POSTGRES_PASSWORD=%s\n' "$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')" > .env
    echo "created .env (generated POSTGRES_PASSWORD)"
else
    echo ".env exists; kept"
fi

if [ ! -s .env.tailscale ]; then
    grep '^TS_AUTHKEY=' "$SOURCE_ENV" > .env.tailscale || {
        echo "TS_AUTHKEY not found in $SOURCE_ENV" >&2
        rm -f .env.tailscale
        exit 1
    }
    echo "created .env.tailscale (TS_AUTHKEY copied from the source)"
else
    echo ".env.tailscale exists; kept"
fi

chmod 600 .env .env.tailscale
