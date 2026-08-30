#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include "da_params.h"

uint8_t *read_file(const char *path, uint32_t *size);
int analyze_preloader(const uint8_t *data, uint32_t size, uint32_t base,
                      uint32_t *ptr_dl, uint32_t *ptr_ul,
                      uint32_t *bldr_jump, uint32_t *da_addr,
                      uint32_t *lk_base);
void inject_params(uint8_t *payload, uint32_t payload_size,
                   const payload_params_t *params);

#endif // UTIL_H
