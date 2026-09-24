#ifndef DA_PARAMS_H
#define DA_PARAMS_H

#include "common.h"

typedef enum {
    SOC_MT6572 = 0,
    SOC_MT6582,
    SOC_MT6595,
    SOC_MT6589,
    SOC_UNKNOWN
} soc_type_t;

void payload_params_init(payload_params_t *p, uint32_t mem_start, uint32_t mem_end,
                         uint32_t dl, uint32_t ul, soc_type_t soc);

#endif // DA_PARAMS_H
