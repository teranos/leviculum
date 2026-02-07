#!/usr/bin/env bash
# Cargo runner for T114 — builds UF2 from ELF and deploys to bootloader.
# Invoked automatically by `cargo run` via .cargo/config.toml.
#
# Pipeline: ELF → flat binary (objcopy) → UF2 (bin2uf2) → copy to UF2 drive
#
# NOTE: --base must match FLASH ORIGIN in memory.x (currently 0x26000 for S140 v6)

set -euo pipefail

ELF="${1:?Usage: uf2-runner.sh <ELF>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NRF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="$NRF_DIR/target"
BIN_FILE="$ELF.bin"
UF2_FILE="$ELF.uf2"
UF2_TIMEOUT="${UF2_TIMEOUT:-30}"

FLASH_BASE=0x26000
FAMILY_ID=0xADA52840

# --- Step 1: Find objcopy ---------------------------------------------------

find_objcopy() {
    # Try llvm-objcopy from rustup first
    local sysroot
    sysroot="$(rustc --print sysroot 2>/dev/null || true)"
    if [ -n "$sysroot" ]; then
        local candidate
        candidate="$(find "$sysroot/lib/rustlib" -name llvm-objcopy -type f 2>/dev/null | head -1)"
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            echo "$candidate"
            return
        fi
    fi
    # Try llvm-objcopy in PATH
    if command -v llvm-objcopy >/dev/null 2>&1; then
        echo "llvm-objcopy"
        return
    fi
    # Try arm-none-eabi-objcopy in PATH
    if command -v arm-none-eabi-objcopy >/dev/null 2>&1; then
        echo "arm-none-eabi-objcopy"
        return
    fi
    echo ""
}

OBJCOPY="$(find_objcopy)"
if [ -z "$OBJCOPY" ]; then
    echo "Error: No objcopy found. Install one of:" >&2
    echo "  rustup component add llvm-tools   (recommended)" >&2
    echo "  apt install gcc-arm-none-eabi" >&2
    exit 1
fi

# --- Step 2: Build bin2uf2 (cached) -----------------------------------------

BIN2UF2="$TARGET_DIR/bin2uf2"
BIN2UF2_SRC="$SCRIPT_DIR/bin2uf2.rs"

if [ ! -f "$BIN2UF2" ] || [ "$BIN2UF2_SRC" -nt "$BIN2UF2" ]; then
    echo "==> Building bin2uf2 tool"
    mkdir -p "$TARGET_DIR"
    rustc "$BIN2UF2_SRC" -o "$BIN2UF2" --edition 2021
fi

# --- Step 3: ELF → flat binary ----------------------------------------------

echo "==> Converting ELF to binary ($(basename "$OBJCOPY"))"
# -R .bss -R .uninit: exclude NOBITS sections so the binary only contains FLASH
# content. Without this, a pre-2020 llvm-objcopy bug could include .bss (VMA in
# RAM at 0x20003000), producing a ~500 MB binary and wrong UF2 target addresses.
"$OBJCOPY" -O binary -R .bss -R .uninit "$ELF" "$BIN_FILE"

# Sanity check: firmware must fit in application region (824K = 0xCE000 bytes).
# If the binary is larger, something went wrong (e.g. NOBITS leak or wrong ELF).
BIN_SIZE="$(stat -c%s "$BIN_FILE")"
MAX_SIZE=$((0xCE000))
if [ "$BIN_SIZE" -gt "$MAX_SIZE" ]; then
    echo "Error: Binary is ${BIN_SIZE} bytes, exceeds application region (${MAX_SIZE} bytes)." >&2
    echo "       This would overwrite the bootloader. Aborting." >&2
    rm -f "$BIN_FILE"
    exit 1
fi

# --- Step 4: Binary → UF2 ---------------------------------------------------

echo "==> Converting binary to UF2 (base: $FLASH_BASE, family: nRF52840)"
"$BIN2UF2" --base "$FLASH_BASE" --family "$FAMILY_ID" "$BIN_FILE" "$UF2_FILE"

# --- Step 5: Find UF2 drive -------------------------------------------------

find_uf2_drive() {
    local search_dirs=()
    # Standard Linux automount locations
    if [ -d "/media/$USER" ]; then
        search_dirs+=("/media/$USER")
    fi
    if [ -d "/run/media/$USER" ]; then
        search_dirs+=("/run/media/$USER")
    fi
    if [ -d "/mnt" ]; then
        search_dirs+=("/mnt")
    fi

    for dir in "${search_dirs[@]}"; do
        local info
        info="$(find "$dir" -maxdepth 2 -name INFO_UF2.TXT -type f 2>/dev/null | head -1)"
        if [ -n "$info" ]; then
            dirname "$info"
            return
        fi
    done

    # Try mounting unmounted small removable block devices via udisksctl
    if command -v udisksctl >/dev/null 2>&1; then
        for dev in /dev/sd?; do
            [ -b "$dev" ] || continue
            # Only consider small devices (< 64MB, typical for UF2 bootloaders)
            local size
            size="$(cat "/sys/block/$(basename "$dev")/size" 2>/dev/null || echo 0)"
            # size is in 512-byte sectors; 64MB = 131072 sectors
            if [ "$size" -gt 0 ] && [ "$size" -lt 131072 ]; then
                local part="${dev}1"
                [ -b "$part" ] || part="$dev"
                local mount_output
                mount_output="$(udisksctl mount -b "$part" 2>/dev/null || true)"
                if [ -n "$mount_output" ]; then
                    local mount_point
                    mount_point="$(echo "$mount_output" | grep -oP 'at \K/.*' || true)"
                    if [ -n "$mount_point" ] && [ -f "$mount_point/INFO_UF2.TXT" ]; then
                        echo "$mount_point"
                        return
                    fi
                fi
            fi
        done
    fi

    echo ""
}

UF2_DRIVE="$(find_uf2_drive)"

# --- Step 6: Prompt + wait --------------------------------------------------

if [ -z "$UF2_DRIVE" ]; then
    echo "==> Looking for UF2 drive..."
    echo "    ┌──────────────────────────────────────────────────┐"
    echo "    │  Double-tap RESET on T114 to enter bootloader.   │"
    echo "    └──────────────────────────────────────────────────┘"
    echo "==> Waiting for UF2 drive (${UF2_TIMEOUT}s)..."

    max_ticks=$((UF2_TIMEOUT * 2))  # 0.5s per tick
    tick=0
    while [ "$tick" -lt "$max_ticks" ]; do
        sleep 0.5
        tick=$((tick + 1))
        UF2_DRIVE="$(find_uf2_drive)"
        if [ -n "$UF2_DRIVE" ]; then
            break
        fi
    done

    if [ -z "$UF2_DRIVE" ]; then
        echo "" >&2
        echo "==> Timeout: No UF2 drive found after ${UF2_TIMEOUT}s." >&2
        echo "    UF2 file ready at: $UF2_FILE" >&2
        echo "    To flash manually:" >&2
        echo "      1. Double-tap RESET on T114" >&2
        echo "      2. cp $UF2_FILE /media/$USER/NRF52BOOT/NEW.UF2" >&2
        echo "      3. sync" >&2
        exit 1
    fi
fi

# --- Step 7: Deploy ---------------------------------------------------------

DRIVE_NAME="$(basename "$UF2_DRIVE")"
echo "==> Found: $UF2_DRIVE ($DRIVE_NAME)"
echo "==> Deploying firmware.uf2..."
cp "$UF2_FILE" "$UF2_DRIVE/NEW.UF2"
sync

# --- Step 9: Boot verification ----------------------------------------------

echo "==> Waiting for device to boot..."

# Wait for UF2 drive to disappear (bootloader finished flashing)
for _ in $(seq 1 20); do
    if [ ! -d "$UF2_DRIVE" ] || [ ! -f "$UF2_DRIVE/INFO_UF2.TXT" ]; then
        break
    fi
    sleep 0.5
done

# Wait for ttyACM device to appear (application booted)
BOOT_TIMEOUT=20  # ticks at 0.5s each = 10 seconds
boot_tick=0
TTY_PORT=""
while [ "$boot_tick" -lt "$BOOT_TIMEOUT" ]; do
    for tty in /dev/ttyACM*; do
        if [ -c "$tty" ]; then
            TTY_PORT="$tty"
            break 2
        fi
    done
    sleep 0.5
    boot_tick=$((boot_tick + 1))
done

if [ -n "$TTY_PORT" ]; then
    echo "==> Device booted: $TTY_PORT"
else
    echo "==> Warning: Device did not enumerate a serial port within 10s." >&2
    echo "    Firmware may have crashed, or USB CDC-ACM is not enabled." >&2
fi

# --- Step 10: Clean up ------------------------------------------------------

rm -f "$BIN_FILE"

echo "==> Done!"
