#include "soc_db.h"
#include "common.h"
#include <stddef.h>

const soc_info_t soc_mt6589 = {
    .hw_code = 0x6583,
    .name = "MT6589",
    .dram_base = 0x80000000,
    .uart0_base = 0x11006000,
    .wdt_base = 0x10000000,
    .boot_arg_addr = 0x800A0000,
    .payload_flags = PAYLOAD_FLAG_DISABLE_WDT,
    .lk_kernel_addr = 0x80008000,
    .lk_ramdisk_addr = 0x84000000,
    .lk_fastboot_payload_min_addr = 0x88000000,
};

const soc_info_t soc_mt6572 = {
    .hw_code = 0x6572,
    .name = "MT6572",
    .dram_base = 0x80000000,
    .uart0_base = 0x11005000,
    .wdt_base = 0x10000000,
    .boot_arg_addr = 0x800A0000,
};

const soc_info_t soc_mt6582 = {
    .hw_code = 0x6582,
    .name = "MT6582",
    .dram_base = 0x80000000,
    .uart0_base = 0x11002000,
    .wdt_base = 0x10000000,
    .boot_arg_addr = 0x800A0000,
};

const soc_info_t soc_mt6595 = {
    .hw_code = 0x6595,
    .name = "MT6595",
    .dram_base = 0x40000000,
    .uart0_base = 0x11002000,
    .wdt_base = 0x10000000,
    .boot_arg_addr = 0x800A0000,
};

static const soc_info_t *soc_list[] = {
    &soc_mt6589,
    &soc_mt6572,
    &soc_mt6582,
    &soc_mt6595,
    NULL
};

const soc_info_t *soc_get_by_hw_code(uint16_t hw_code) {
    for (int i = 0; soc_list[i]; i++) {
        if (soc_list[i]->hw_code == hw_code) return soc_list[i];
    }
    return NULL;
}
