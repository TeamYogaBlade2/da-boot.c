#ifndef SOC_DB_H
#define SOC_DB_H

#include <stdint.h>

typedef struct soc_info {
    uint32_t hw_code;
    const char *name;
    uint32_t dram_base;
    uint32_t uart0_base;
    uint32_t wdt_base;
    uint32_t wdt_reset_offset;
    uint32_t da_ram_addr;
    uint32_t lk_base_hint;
    uint32_t boot_arg_addr;
    int part_t_startblk_offset;
} soc_info_t;

const soc_info_t *soc_get_by_hw_code(uint16_t hw_code);
const soc_info_t *soc_get_by_name(const char *name);

// 定義済みSoC
extern const soc_info_t soc_mt6589;
extern const soc_info_t soc_mt6572;
extern const soc_info_t soc_mt6582;
extern const soc_info_t soc_mt6595;

#endif // SOC_DB_H
