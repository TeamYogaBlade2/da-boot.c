#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

int image_parse_preloader(const uint8_t *data, uint32_t size,
                          uint32_t *load_addr, uint32_t *jump_offset,
                          uint32_t *content_offset, uint32_t *content_size);
int image_parse_lk(const uint8_t *data, uint32_t size,
                   uint32_t *content_offset, uint32_t *content_size,
                   char *partition_name, uint32_t name_len);

#endif // IMAGE_H
