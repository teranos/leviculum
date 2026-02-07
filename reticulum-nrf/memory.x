/* nRF52840 memory layout — Adafruit nRF52 bootloader with SoftDevice S140 v6 */
/* NOTE: FLASH ORIGIN must match --base in tools/uf2-runner.sh */
MEMORY
{
    /* Application starts after SoftDevice S140 v6 at 0x26000 (152K) */
    /* Bootloader at 0xF4000, app space = 0xF4000 - 0x26000 = 0xCE000 (824K) */
    FLASH : ORIGIN = 0x00026000, LENGTH = 0xCE000

    /* SoftDevice S140 v6.1.1 remains active after bootloader handoff.     */
    /* It reserves RAM from 0x20000000 for its own state (~12 KB).         */
    /* Application RAM must start after the SoftDevice reserved region.    */
    /* 0x20003000 = 12 KB reserved; leaves 244 KB for application.         */
    RAM   : ORIGIN = 0x20003000, LENGTH = 0x3D000
}
