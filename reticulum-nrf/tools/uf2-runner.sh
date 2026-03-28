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

    # Try mounting unmounted small removable block devices
    for dev in /dev/sd?; do
        [ -b "$dev" ] || continue
        # Only consider small devices (< 64MB, typical for UF2 bootloaders)
        local size
        size="$(cat "/sys/block/$(basename "$dev")/size" 2>/dev/null || echo 0)"
        # size is in 512-byte sectors; 64MB = 131072 sectors
        if [ "$size" -gt 0 ] && [ "$size" -lt 131072 ]; then
            local part="${dev}1"
            [ -b "$part" ] || part="$dev"

            # Try udisksctl first (user-level, no sudo)
            if command -v udisksctl >/dev/null 2>&1; then
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

            # Fallback: sudo mount to /mnt
            if sudo -n mount "$part" /mnt 2>/dev/null; then
                if [ -f /mnt/INFO_UF2.TXT ]; then
                    echo "/mnt"
                    return
                fi
                sudo -n umount /mnt 2>/dev/null
            fi
        fi
    done

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

# UF2 bootloaders intercept FAT filesystem writes and check each 512-byte
# sector for UF2 magic. Write the file via cp (same approach as uf2conv.py
# and the Heltec Arduino toolchain). No sync — the bootloader processes
# blocks as they arrive and resets when done; explicit sync races with
# the device disconnect.
UF2_SIZE="$(stat -c%s "$UF2_FILE")"
UF2_BLOCKS=$((UF2_SIZE / 512))
echo "==> Deploying firmware.uf2 (${UF2_SIZE} bytes, ${UF2_BLOCKS} blocks)..."
if [ -w "$UF2_DRIVE" ]; then
    cp "$UF2_FILE" "$UF2_DRIVE/NEW.UF2"
    sync
else
    sudo cp "$UF2_FILE" "$UF2_DRIVE/NEW.UF2"
    sudo sync
fi
# sync may return I/O errors because the bootloader resets after
# processing the last UF2 block — this is normal and expected.

# --- Step 8: Boot verification ----------------------------------------------

echo "==> Waiting for device to boot..."

# Wait for UF2 drive to disappear (bootloader finished flashing)
for _ in $(seq 1 20); do
    if [ ! -d "$UF2_DRIVE" ] || [ ! -f "$UF2_DRIVE/INFO_UF2.TXT" ]; then
        break
    fi
    sleep 0.5
done

# Wait for our USB device to appear — match by VID:PID 1209:0001
BOOT_TIMEOUT=20  # ticks at 0.5s each = 10 seconds
boot_tick=0
OUR_PORTS=""
while [ "$boot_tick" -lt "$BOOT_TIMEOUT" ]; do
    OUR_PORTS=""
    for tty in /dev/ttyACM*; do
        [ -c "$tty" ] || continue
        vid="$(udevadm info -q property "$tty" 2>/dev/null | grep '^ID_VENDOR_ID=' | cut -d= -f2 || true)"
        pid="$(udevadm info -q property "$tty" 2>/dev/null | grep '^ID_MODEL_ID=' | cut -d= -f2 || true)"
        if [ "$vid" = "1209" ] && [ "$pid" = "0001" ]; then
            OUR_PORTS="${OUR_PORTS:+$OUR_PORTS }$tty"
        fi
    done
    if [ -n "$OUR_PORTS" ]; then
        # Wait for udev to settle and create symlinks
        sleep 0.5
        break
    fi
    sleep 0.5
    boot_tick=$((boot_tick + 1))
done

# --- Step 9: Identify ports ------------------------------------------------

DEBUG_PORT=""
TRANSPORT_PORT=""
SERIAL=""

if [ -n "$OUR_PORTS" ]; then
    for port in $OUR_PORTS; do
        iface="$(udevadm info -q property "$port" 2>/dev/null | grep '^ID_USB_INTERFACE_NUM=' | cut -d= -f2 || true)"
        case "$iface" in
            00) DEBUG_PORT="$port" ;;
            02) TRANSPORT_PORT="$port" ;;
        esac
        if [ -z "$SERIAL" ]; then
            SERIAL="$(udevadm info -q property "$port" 2>/dev/null | grep '^ID_SERIAL_SHORT=' | cut -d= -f2 || true)"
        fi
    done

    # Check for udev symlinks
    DEBUG_SYMLINK=""
    TRANSPORT_SYMLINK=""
    if [ -L "/dev/leviculum-debug" ]; then
        DEBUG_SYMLINK="/dev/leviculum-debug"
    fi
    if [ -L "/dev/leviculum-transport" ]; then
        TRANSPORT_SYMLINK="/dev/leviculum-transport"
    fi

    if [ -n "$SERIAL" ]; then
        echo "==> Firmware booted (serial: $SERIAL)"
    else
        echo "==> Firmware booted"
    fi

    if [ -n "$DEBUG_PORT" ]; then
        if [ -n "$DEBUG_SYMLINK" ]; then
            echo "    Debug:     $DEBUG_PORT ($DEBUG_SYMLINK)"
        else
            echo "    Debug:     $DEBUG_PORT"
        fi
    fi

    if [ -n "$TRANSPORT_PORT" ]; then
        if [ -n "$TRANSPORT_SYMLINK" ]; then
            echo "    Transport: $TRANSPORT_PORT ($TRANSPORT_SYMLINK)"
        else
            echo "    Transport: $TRANSPORT_PORT"
        fi
    fi

    if [ -z "$DEBUG_SYMLINK" ] && [ -z "$TRANSPORT_SYMLINK" ]; then
        echo "    Tip: install udev/99-leviculum.rules for stable /dev/leviculum-* symlinks"
    fi

    # Write debug port to target/debug-port for tooling (prefer udev symlink)
    mkdir -p "$TARGET_DIR"
    if [ -n "$DEBUG_SYMLINK" ]; then
        echo "$DEBUG_SYMLINK" > "$TARGET_DIR/debug-port"
    elif [ -n "$DEBUG_PORT" ]; then
        echo "$DEBUG_PORT" > "$TARGET_DIR/debug-port"
    fi
else
    echo "==> Warning: Device did not enumerate serial ports within 10s." >&2
    echo "    Firmware may have crashed, or USB CDC-ACM is not enabled." >&2
fi

# --- Step 11: Clean up ------------------------------------------------------

# Unmount /mnt if we mounted there
if [ "$UF2_DRIVE" = "/mnt" ]; then
    sudo -n umount /mnt 2>/dev/null || true
fi

rm -f "$BIN_FILE"

echo "==> Done!"
