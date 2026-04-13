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
        # RNS_REQUIRE_SHARED is set on the container env so that Python tools
        # (rnprobe, rnpath, rncp, rnstatus, …) launched via `docker exec` fail
        # loudly when they cannot reach the daemon. rnsd itself IS the daemon
        # — with the var set, the vendored RNS patch refuses to start
        # ("started as shared instance"). Strip it for the daemon process only.
        unset RNS_REQUIRE_SHARED
        exec python3 -m RNS.Utilities.rnsd -v --config /root/.reticulum
        ;;
    *)
        echo "Unknown NODE_TYPE: ${NODE_TYPE}" >&2
        exit 1
        ;;
esac
