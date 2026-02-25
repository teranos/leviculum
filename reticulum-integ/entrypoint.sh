#!/bin/bash
set -e

# Ensure Python output is unbuffered so docker logs captures rnsd output
export PYTHONUNBUFFERED=1

# Install RNS from mounted vendor dir if available
if [ -d /opt/vendor/Reticulum ] && ! python3 -c "import RNS" 2>/dev/null; then
    # Copy to temp dir since vendor mount is read-only and pip needs to write build artifacts
    tmp_src=$(mktemp -d)
    cp -r /opt/vendor/Reticulum/* "$tmp_src/"
    pip3 install --break-system-packages "$tmp_src"
    rm -rf "$tmp_src"
fi

case "${NODE_TYPE}" in
    rust)
        exec /usr/local/bin/lrnsd -v --config /root/.reticulum
        ;;
    python)
        exec python3 -m RNS.Utilities.rnsd -v --config /root/.reticulum
        ;;
    *)
        echo "Unknown NODE_TYPE: ${NODE_TYPE}" >&2
        exit 1
        ;;
esac
