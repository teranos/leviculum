/* nRF52840 memory layout — Adafruit nRF52 bootloader with SoftDevice S140 v6 */
/* NOTE: FLASH ORIGIN must match --base in tools/uf2-runner.sh */
MEMORY
{
    /* Application starts after SoftDevice S140 v6 at 0x26000 (152K).        */
    /* Heltec reserves 0xED000-0xF4000 (28K) for license/version data        */
    /* (HARD_VERSION_ADDR, HT_LICENSE_ADDR in variant.h). Bootloader at      */
    /* 0xF4000. Last app page (0xEC000) reserved for identity persistence.  */
    /* Safe app space = 0xEC000 - 0x26000 = 0xC6000 (792K).                 */
    FLASH : ORIGIN = 0x00026000, LENGTH = 0xC6000

    /* SoftDevice S140 v6.1.1 remains active after bootloader handoff.       */
    /* It reserves RAM from 0x20000000 for BLE stack state. Reservation      */
    /* size depends on ATT table, MTU, concurrent connections. Heltec's      */
    /* tested linker (nrf52840_s140_v6.ld) reserves 24 KB (origin 0x6000).  */
    /* Matches vendor/Heltec_nRF52 boards.txt maximum_data_size = 237568.    */
    /* 0x20006000 = 24 KB reserved; leaves 232 KB for application.           */
    RAM   : ORIGIN = 0x20006000, LENGTH = 0x3A000
}
