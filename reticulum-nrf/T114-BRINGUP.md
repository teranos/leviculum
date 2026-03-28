# T114 LNode Bringup Notes

Status as of 2026-03-28. Hardware: Heltec Mesh Node T114 (nRF52840, 256 KB RAM, 1 MB flash).

## What Works

The T114 runs a Reticulum endpoint node. Confirmed on real hardware:

- **Embassy executor** with RTC1 time driver, async tasks, Timer
- **USB CDC-ACM** composite device (port 0 = debug log, port 1 = transport)
- **Hardware RNG** via `embassy_nrf::rng::Rng::new_blocking(p.RNG)`
- **NodeCore** with `EmbeddedStorage` (heapless collections), identity generation, probe responder
- **Serial task** receives HDLC-framed packets from host, deframes correctly
- **set_interface_name / set_interface_hw_mtu** work (with workaround, see below)
- **Heartbeat LED** confirms main loop is alive (short flash every 5s)
- **Panic handler** blinks LED rapidly via raw GPIO register writes

## What Doesn't Work Yet

The main loop receives HDLC frames from the desktop lnsd (confirmed: `frame complete 167` in serial task log), but:

1. **Packets don't reach NodeCore** — `info!("RX {} bytes")` never appears after `handle_packet`
2. **handle_timeout doesn't produce actions** — the probe announce at 15s should emit `Broadcast` actions but `timeout: N actions` never appears in debug log
3. **No bidirectional packet exchange** — lnsd sends its announce, T114 deframes it, but NodeCore doesn't process it and T114 doesn't send its own announce

The serial task pushes deframed data to `incoming_tx.send(data).await`. The main loop does `select(serial.incoming_rx.receive(), Timer::at(deadline))`. The select works (heartbeat fires), but the First arm (incoming packet) apparently never triggers despite the serial task successfully deframing packets.

## Constraints Discovered

### 1. UF2 Flash Size Limit (~780 KB UF2 / ~390 KB text)

The VM USB passthrough truncates large UF2 writes. The Adafruit UF2 bootloader resets before the kernel finishes flushing the page cache for files > ~780 KB.

**Symptoms:** LED dark (firmware corrupt), no USB enumeration. Smaller firmware flashes fine.

**Fix:** Use `opt-level = "z"` + `lto = true` + `codegen-units = 1` in `[profile.release]`. Reduces text from 447 KB to 174 KB. Already in `Cargo.toml`.

**Root cause:** `cp` writes to the page cache, `sync` flushes asynchronously. For large files through VM USB passthrough, the flush is too slow and the bootloader's timeout expires.

**Not tried yet:** Flashing from the host machine directly (no VM), or using `adafruit-nrfutil dfu serial` (Nordic DFU protocol over serial, not mass storage). Either would bypass the size limit.

### 2. BTreeMap Allocation After NodeCore::build() Panics

Any `BTreeMap::new()` followed by `insert()` after `NodeCoreBuilder::build()` panics. Suspected cause: `embedded-alloc` LlffHeap fragmentation after NodeCore's large allocations.

**Symptoms:** Panic handler rapid LED blink.

**Fix:** Pre-allocate `BTreeMap::new()` BEFORE `NodeCoreBuilder::build()`:

```rust
let ifac_configs: BTreeMap<usize, IfacConfig> = BTreeMap::new();  // BEFORE build
let mut node = NodeCoreBuilder::new()...build(...);               // AFTER
```

`BTreeMap::new()` doesn't allocate (empty tree), but having it in scope before NodeCore means any future insert's allocation request goes to a different heap state.

**Not investigated:** Whether `embedded-alloc` has alignment bugs for BTreeMap node allocations, or whether a different allocator (`linked_list_allocator`, `dlmalloc`) would fix it.

### 3. Boot Blink Must Use nop Delay

`Timer::after_millis(200).await` as the first await point after NodeCore build causes the LED to stay ON (Timer never returns). Using a nop delay loop works:

```rust
led.set_level(Level::Low);
for _ in 0..12_000_000u32 { cortex_m::asm::nop(); }  // ~200ms at 64MHz
led.set_level(Level::High);
```

Timer works fine inside the main loop (heartbeat uses Timer::after_millis(50)). The issue is specific to the first await after NodeCore construction.

### 4. Flash Script (uf2-runner.sh)

`cargo run --release` invokes `tools/uf2-runner.sh`. Fixed for VM environments:

- `udisksctl` fails without polkit agent → fallback to `sudo mount /dev/sdX /mnt`
- Deploy uses `sudo cp` + `sudo sync` + `sudo umount`
- Script finds UF2 drive by searching for `INFO_UF2.TXT` in `/media/$USER`, `/run/media/$USER`, `/mnt`

### 5. VM USB Passthrough

The VM passthrough matches devices by VID:PID. Our firmware uses `1209:0001` (leviculum). The Heltec stock firmware uses `239a:8071`. The bootloader uses `239a:0071`. All three must be in the VM passthrough rules.

Device enumeration after flashing can take 10-15s through the VM. The `uf2-runner.sh` boot verification timeout (10s) often misses it.

### 6. Embassy Async Frame

`NodeCore` with `EmbeddedStorage` is ~40 KB. It lives in the Embassy task's static POOL (async future frame). The POOL is `0x9F20` = 40,736 bytes regardless of whether `handle_packet` code is linked. This is NOT the cause of the dark LED issue (that was the flash size limit).

## Device Map (This Machine)

| Port | Device |
|------|--------|
| `/dev/ttyACM0` or `/dev/ttyACM2` | leviculum T114 — debug (VID 1209, iface 00) |
| `/dev/ttyACM1` or `/dev/ttyACM3` | leviculum T114 — transport (VID 1209, iface 02) |
| Other ACMs with VID 239a | Heltec T114 #2 (stock firmware) |
| Other ACMs with VID 1a86 | LilyGO RNode ESP32 (×2) |

Port numbers shift depending on enumeration order. Always identify by VID + interface number:
```bash
for dev in /dev/ttyACM*; do
    vid=$(udevadm info -q property "$dev" | grep '^ID_VENDOR_ID=' | cut -d= -f2)
    iface=$(udevadm info -q property "$dev" | grep '^ID_USB_INTERFACE_NUM=' | cut -d= -f2)
    echo "$dev  VID=$vid iface=$iface"
done
```

## What To Try Next

### Priority 1: Debug Why Packets Don't Reach NodeCore

The serial task deframes packets and calls `incoming_tx.send(data).await`. The main loop does `select(serial.incoming_rx.receive(), Timer::at(deadline))`. The heartbeat fires (Timer arm works), but the channel arm apparently doesn't.

Hypotheses:
- **Channel sender/receiver mismatch** — `SerialChannels` returns `INCOMING_CHANNEL.receiver()` and the serial task uses `INCOMING_CHANNEL.sender()`. But both are static channels with capacity 8. Verify the sender and receiver are from the same channel instance.
- **`send().await` blocks** — if the channel is full (8 slots), `send` blocks. But the main loop should be draining it. Unless the main loop never reaches the `select` (stuck earlier).
- **Deframer produces wrong data** — the `frame complete 167` log shows a frame was produced, but maybe the data is empty or corrupt.

Diagnostics to add:
```rust
// In main loop, before select:
info!("loop deadline_ms={}", deadline.as_millis());

// In serial task, after incoming_tx.send:
log_u32("SER: sent to channel", data.len() as u32);

// In main loop, after select returns:
// (already has info!("RX {} bytes") — if this never prints, the First arm never fires)
```

### Priority 2: Debug Why handle_timeout Returns Empty

After 15s, `handle_timeout()` should trigger the probe responder's management announce. `TickOutput.actions` should contain a `Broadcast` action. If it's empty, either:
- `next_mgmt_announce_ms` is not set (probe responder not activated)
- `EmbassyClock::now_ms()` returns wrong values (check: is Embassy Instant epoch-based or boot-based?)
- The probe responder's destination wasn't properly registered

Diagnostic:
```rust
// Before main loop:
info!("next_deadline={:?}", node.next_deadline());

// In timeout arm:
info!("handle_timeout at now={}", embassy_time::Instant::now().as_millis());
```

### Priority 3: Test Bidirectional Packet Exchange

Once packets reach NodeCore:
1. Start lnsd with `respond_to_probes = yes` on the desktop
2. lnsd sends its announce at 15s → T114 receives and processes it
3. T114 sends its announce at 15s → lnsd receives via serial

Expected log on T114: `RX 167 bytes` (lnsd's announce)
Expected log on lnsd: announce received from T114's identity hash

### Priority 4: Investigate Flash Size Limit

If larger firmware is needed in the future:
- Try flashing from the host machine directly (not through VM)
- Try `adafruit-nrfutil dfu serial --package firmware.zip -p /dev/ttyACMx -b 115200 -t 1200`
- Try `uf2conv.py -d /media/T114BOOT firmware.uf2`
- The `opt-level = "z"` + LTO keeps the binary at 174 KB for now, well under the limit

## Flash Procedure

```bash
# 1. Double-tap reset on T114 to enter DFU mode
# 2. From reticulum-nrf/:
cargo run --release
# This builds, converts to UF2, finds the bootloader drive, and flashes.

# Manual flash (if cargo run times out):
sudo mount /dev/sdX /mnt        # X = whatever the bootloader enumerated as
sudo cp target/thumbv7em-none-eabihf/release/t114.uf2 /mnt/NEW.UF2
sudo sync
sudo umount /mnt
```

## Binary Size Budget

| Component | Size |
|-----------|------|
| Text (code + rodata) | 174 KB |
| Data (initialized) | 24 bytes |
| BSS (zero-init, includes 96 KB heap + 40 KB async frame + heapless collections) | 146 KB |
| Stack (RAM_END - BSS_END) | ~86 KB |
| **Total RAM** | **232 KB / 232 KB available** |
| **Total Flash** | **174 KB / 796 KB available** |
