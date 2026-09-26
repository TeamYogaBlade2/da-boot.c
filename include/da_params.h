#ifndef DA_PARAMS_H
#define DA_PARAMS_H

#include "common.h"

void payload_params_init(payload_params_t *p, uint32_t mem_start, uint32_t mem_end,
                         uint32_t dl, uint32_t ul, uint32_t uart0_base,
                         uint32_t wdt_base, uint32_t flags);

#endif // DA_PARAMS_H
