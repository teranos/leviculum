/* nRF52840 memory layout — Adafruit-style bootloader with SoftDevice S140 v7.3.0 */
/* NOTE: FLASH ORIGIN must match --base in tools/uf2-runner.sh */
/* Bug32-softdevice-spike Day 3: bumped from v6.1.1 to v7.3.0 to match    */
/* nrf-softdevice's supported S140 family. Both Pocket V2 and T114 ship   */
/* with v6.1.1 from factory; the spike installs v7.3.0 once via UF2-mass- */
/* storage flash. Old (v6.1.1) numbers in comments for reference.         */
MEMORY
{
    /* Application starts after SoftDevice S140 v7.3.0 at 0x27000 (156K).    */
    /* (Was v6.1.1 at 0x26000=152K.)                                         */
    /* Heltec reserves 0xED000-0xF4000 (28K) for license/version data        */
    /* (HARD_VERSION_ADDR, HT_LICENSE_ADDR in variant.h). Bootloader at      */
    /* 0xF4000. Last app page (0xEC000) reserved for identity persistence.  */
    /* Safe app space = 0xEC000 - 0x27000 = 0xC5000 (788K).                 */
    FLASH : ORIGIN = 0x00027000, LENGTH = 0xC5000

    /* SoftDevice S140 v7.3.0 RAM reservation: 48 KiB (conservative,        */
    /* empirically clean on both T114 and Pocket V2; was the pre-batch      */
    /* committed value). The pre-Day-4 reviewer batch (2026-05-02)          */
    /* attempted to pin a tighter canonical and could not, hence this       */
    /* over-reservation is intentional. Details:                            */
    /*                                                                      */
    /*   * Stage 1 (`nrf-softdevice/log` feature): destabilized the build  */
    /*     with attribution uncertain (possibly correlated with the 64K    */
    /*     peripheral-MEMACC layout-shift bug rather than the log feature  */
    /*     itself). Reverted.                                               */
    /*                                                                      */
    /*   * Stage 2 (deliberate undersize → NoMem panic): blocked by S140   */
    /*     v7's unconditional 8 KiB MBR + master-init RAM reservation at   */
    /*     0x20000000-0x20001FFF; any RAM ORIGIN ≤ 0x20002000 HardFaults    */
    /*     before `sd_ble_enable` can return its helpful NoMem panic.       */
    /*                                                                      */
    /*   * Option C (local Cargo `[patch]` of nrf-softdevice's              */
    /*     `softdevice.rs:243` to expose `wanted_app_ram_base` via an       */
    /*     `extern "Rust"` callback): set up cleanly (cargo tree confirmed */
    /*     the patched paths), but the patched build entered a panic-loop  */
    /*     on T114 at 16 KiB before USB enumerated, so the [BUG32_RAM]     */
    /*     line was never captured. Root cause not isolated within the     */
    /*     reviewer's 30-minute Option-C time-box; spec said fall back.   */
    /*                                                                      */
    /*   * Option A 16 KiB fallback: smoke-tested on this branch HEAD;     */
    /*     T114 enumerated briefly then disconnected (port disappeared    */
    /*     mid-smoke, host re-enumerated it), confirming 16 KiB is in     */
    /*     fact too tight for our config — the reviewer's spec assumed    */
    /*     "16 K is sure to be too small" was *correct*; our earlier       */
    /*     "16 K boots clean" observation was a brief partial-boot, not   */
    /*     a sustained-running state. Bumped to 48 KiB.                   */
    /*                                                                      */
    /* Canonical bound: 16 KiB < canonical ≤ 48 KiB. Exact value unpinned. */
    /*                                                                      */
    /* T114 has a separate per-binary instability at 48 KiB on this HEAD:  */
    /* both T114-A (today's many panic-loop cycles) AND a freshly-attached */
    /* T114-B exhibit "USB CDC port appears for milliseconds then drops".  */
    /* RAK4631 is stable at the same 48 KiB build. Per reviewer's          */
    /* decision rule, Day 4 proceeds on RAK4631 only; T114 issue tracked  */
    /* as separate post-spike investigation.                               */
    /*                                                                      */
    /* Stay below the 0x20010000 (64 KiB) boundary; that triggers a        */
    /* peripheral-register MEMACC fault distinct from this RAM-NoMem path  */
    /* and is tracked separately as a follow-up item.                       */
    /*                                                                      */
    /* Leaves 256K - 48K = 208K (0x34000) for application.                  */
    RAM   : ORIGIN = 0x2000C000, LENGTH = 0x34000
}
