#!/usr/bin/env bash
# Builds the two nightly tarballs from the compiled musl binaries.
# Called from .woodpecker/nightly.yml after both arch builds finish.
#
# Expects:
#   target/x86_64-unknown-linux-musl/release/{lnsd,lns,lncp}
#   target/aarch64-unknown-linux-musl/release/{lnsd,lns,lncp}
#   LEVICULUM_BUILD_ID env var (for the versioned README line)
#
# Produces under dist/:
#   leviculum-nightly-linux-amd64.tar.gz + .sha256
#   leviculum-nightly-linux-arm64.tar.gz + .sha256

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_ID="${LEVICULUM_BUILD_ID:-unknown}"
DIST="dist"
rm -rf "$DIST"
mkdir -p "$DIST"

pack_arch() {
    local arch_dash="$1"    # amd64 | arm64
    local rust_triple="$2"  # x86_64-unknown-linux-musl | aarch64-unknown-linux-musl

    local name="leviculum-nightly-linux-${arch_dash}"
    local stage="$DIST/$name"
    local src="target/${rust_triple}/release"

    mkdir -p "$stage/bin" "$stage/doc"

    for bin in lnsd lns lncp; do
        cp "$src/$bin" "$stage/bin/$bin"
        strip "$stage/bin/$bin" 2>/dev/null || true
    done

    cp README.md LICENSE CHANGELOG.md "$stage/doc/"

    cat >"$stage/VERSION" <<EOF
leviculum nightly build
build-id: ${BUILD_ID}
arch: linux-${arch_dash}
EOF

    tar -C "$DIST" -czf "$DIST/$name.tar.gz" "$name"
    rm -rf "$stage"

    (cd "$DIST" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
}

pack_arch amd64 x86_64-unknown-linux-musl
pack_arch arm64 aarch64-unknown-linux-musl

echo "=== dist/ ==="
ls -la "$DIST"
