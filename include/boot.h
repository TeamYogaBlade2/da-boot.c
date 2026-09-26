#ifndef BOOT_H
#define BOOT_H

#include <stddef.h>
#include <stdint.h>

#include "serial.h"

typedef struct {
    const char *path;
    uint32_t addr;
} upload_file_t;

typedef enum {
    LK_BOOT_NORMAL = 0,
    LK_BOOT_META = 1,
    LK_BOOT_RECOVERY = 2,
    LK_BOOT_SW_REBOOT = 3,
    LK_BOOT_FACTORY = 4,
    LK_BOOT_ADVMETA = 5,
    LK_BOOT_ATE_FACTORY = 6,
    LK_BOOT_ALARM = 7,
    LK_BOOT_FASTBOOT = 99,
    LK_BOOT_DOWNLOAD = 100,
} lk_boot_mode_t;

typedef enum {
    BR_POWER_KEY = 0,
    BR_USB,
    BR_RTC,
    BR_WDT,
    BR_WDT_BY_PASS_PWK,
    BR_TOOL_BY_PASS_PWK,
    BR_2SEC_REBOOT,
    BR_UNKNOWN
} boot_reason_t;

int run_preloader_mode(serial_t *s, const struct soc_info *soc,
                       const char *payload_path, const char *preloader_path,
                       const upload_file_t *inputs, size_t input_count,
                       uint32_t preloader_addr_hint, uint32_t jump_addr);

int run_lk_mode(serial_t *s, const struct soc_info *soc,
                const char *payload_path, const char *preloader_path,
                const char *lk_path,
                const upload_file_t *inputs, size_t input_count,
                const char *kernel_path, const char *ramdisk_path,
                uint32_t preloader_addr_hint,
                uint32_t dram_size_per_rank, uint32_t dram_ranks,
                uint32_t lk_mode);

int run_repl_mode(serial_t *s);

#endif
