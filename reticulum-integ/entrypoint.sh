#!/bin/bash
set -e

# Ensure Python output is unbuffered so docker logs captures rnsd output
export PYTHONUNBUFFERED=1

# RNS is pre-installed in the Docker image (see Dockerfile).
# No runtime pip install needed.

case "${NODE_TYPE}" in
    rust)
        exec /usr/local/bin/lnsd -v --config /root/.reticulum
        ;;
    python)
        exec python3 -m RNS.Utilities.rnsd -v --config /root/.reticulum
        ;;
    *)
        echo "Unknown NODE_TYPE: ${NODE_TYPE}" >&2
        exit 1
        ;;
esac
