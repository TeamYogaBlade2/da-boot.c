#ifndef DA_COMMON_H
#define DA_COMMON_H

#include <stdint.h>

#define MAGIC_DA        0xDAB001
#define CURRENT_VERSION 1
#define MAX_BLACKLIST   12

typedef struct {
    uint32_t start;
    uint32_t end;
} mem_range_t;

typedef enum {
    BLACKLIST_NONE = 0,
    BLACKLIST_RELOC,
    BLACKLIST_DL
} blacklist_mode_t;

typedef struct {
    mem_range_t range;
    blacklist_mode_t mode;
} blacklist_range_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    mem_range_t memory;
    blacklist_range_t blacklist[MAX_BLACKLIST];
    uint32_t ptr_dl;
    uint32_t ptr_ul;
    uint32_t soc;
} payload_params_t;

typedef struct {
    uint32_t ptr_bldr_jump;
} preloader_runner_params_t;

typedef struct {
    uint32_t ptr_mt_part_generic_read;
    uint32_t ptr_mt_part_get_partition;
    uint32_t bootimg_scratch_addr;
    uint32_t bootimg_scratch_size;
    uint32_t ptr_mt_boot_init;
    uint32_t ptr_fastboot_init;
    uint32_t ptr_fastboot_register;
    uint32_t ptr_fastboot_okay;
    uint32_t ptr_fastboot_fail;
    uint32_t ptr_udc_stop;
    uint32_t ptr_mtk_wdt_disable;
    uint32_t ptr_mtk_wdt_init;
    uint32_t ptr_boot_linux_from_storage;
    uint32_t boot_mode_addr;
    uint32_t machtype;
} lk_runner_params_t;

_Static_assert(sizeof(lk_runner_params_t) == 60,
               "lk_runner_params_t must remain a 60-byte wire payload");

#define LK_PARAMS_WIRE_SIZE (2u + sizeof(lk_runner_params_t))

#define MT6589_LK_BOOTIMG_READ_SLACK 0x1000u

#endif // DA_COMMON_H
