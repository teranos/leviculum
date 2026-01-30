#!/bin/bash
# Verify reticulum-core builds for all embedded targets
# See doc/EMBEDDED_TARGETS.md for details on supported hardware

set -e

cd "$(dirname "$0")/.."

echo "=== Checking embedded target builds for reticulum-core ==="
echo ""

# Stock rustup targets (work with standard toolchain)
STOCK_TARGETS=(
    "thumbv7em-none-eabihf"  # nRF52840 - ARM Cortex-M4F
    "thumbv6m-none-eabi"      # RP2040 - ARM Cortex-M0+
)

# Xtensa targets (require espup toolchain)
XTENSA_TARGETS=(
    "xtensa-esp32s3-none-elf"  # ESP32-S3
    "xtensa-esp32-none-elf"    # ESP32
)

FAILED=0

# Check stock targets
for target in "${STOCK_TARGETS[@]}"; do
    echo "Building for $target..."
    if cargo build -p reticulum-core --target "$target" 2>&1; then
        echo "  OK: $target"
    else
        echo "  FAILED: $target"
        FAILED=1
    fi
    echo ""
done

# Check Xtensa targets if requested
if [[ "$1" == "--with-xtensa" ]]; then
    echo "=== Checking Xtensa targets (requires espup) ==="
    echo ""

    for target in "${XTENSA_TARGETS[@]}"; do
        echo "Building for $target..."
        if cargo build -p reticulum-core --target "$target" 2>&1; then
            echo "  OK: $target"
        else
            echo "  FAILED: $target"
            FAILED=1
        fi
        echo ""
    done
fi

if [[ $FAILED -eq 0 ]]; then
    echo "=== All builds successful ==="
    exit 0
else
    echo "=== Some builds failed ==="
    exit 1
fi
