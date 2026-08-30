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
int extract_mt_part_generic_read(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *addr);

#endif // PATCHER_H
