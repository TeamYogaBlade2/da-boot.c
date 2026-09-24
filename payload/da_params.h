#ifndef DA_PARAMS_H
#define DA_PARAMS_H

#include "common.h"

// 関数宣言
int find_unused_range(const payload_params_t *p, uint32_t size, mem_range_t *out);
int blacklist_dl(payload_params_t *p, uint32_t start, uint32_t end);
int blacklist_reloc(payload_params_t *p, uint32_t start, uint32_t end);

#endif // DA_PARAMS_H
