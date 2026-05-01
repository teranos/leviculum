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

    /* SoftDevice S140 v7.3.0 reserves the bottom RAM region for BLE stack   */
    /* state. 48K is the smallest tested value that boots T114 cleanly       */
    /* (5-min smoke). 64K introduces a "Softdevice memory access violation"  */
    /* fault — likely linker-layout-related, not a RAM-size issue, since     */
    /* the SD's actual reservation should be < 48K. Sticking with 48K        */
    /* until we identify the specific peripheral access that the SD blocks.  */
    /* Leaves 256K-48K = 208K (0x34000) for application.                     */
    RAM   : ORIGIN = 0x2000C000, LENGTH = 0x34000
}
