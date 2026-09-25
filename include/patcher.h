#ifndef PATCHER_H
#define PATCHER_H

#include <stdint.h>

// Preloader解析
int extract_preloader_dl_ul(const uint8_t *data, uint32_t size, uint32_t base,
                            uint32_t *ptr_dl, uint32_t *ptr_ul);
int extract_lk_base(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *lk_base);
int extract_bldr_jump(const uint8_t *data, uint32_t size, uint32_t base,
                      uint32_t *bldr_jump, uint32_t *da_addr);

// LK解析
int extract_mt_part_get_partition(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *addr);
int extract_get_part(const uint8_t *data, uint32_t size, uint32_t base,
                     uint32_t *addr);
int extract_mt_part_generic_read(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *addr);
int extract_boot_linux_from_storage(const uint8_t *data, uint32_t size,
                                    uint32_t base, uint32_t *addr);
int extract_fastboot_init(const uint8_t *data, uint32_t size, uint32_t base,
                          uint32_t *addr);
int extract_fastboot_register(const uint8_t *data, uint32_t size, uint32_t base,
                              uint32_t *addr);
int extract_mtk_wdt_init(const uint8_t *data, uint32_t size, uint32_t base,
                         uint32_t *addr);
int extract_fastboot_fail(const uint8_t *data, uint32_t size, uint32_t base,
                          uint32_t *addr);
int extract_fastboot_okay(const uint8_t *data, uint32_t size, uint32_t base,
                          uint32_t *addr);
int extract_udc_stop(const uint8_t *data, uint32_t size, uint32_t base,
                     uint32_t *addr);
int extract_mt_boot_init(const uint8_t *data, uint32_t size, uint32_t base,
                         uint32_t *addr);
int extract_boot_mode_addr(const uint8_t *data, uint32_t size, uint32_t base,
                           uint32_t *addr);

int analyze_preloader(const uint8_t *data, uint32_t size, uint32_t base_hint,
                      uint32_t *ptr_dl, uint32_t *ptr_ul,
                      uint32_t *bldr_jump, uint32_t *da_addr,
                      uint32_t *lk_base);

#endif // PATCHER_H
