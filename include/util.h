#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include "da_params.h"

uint8_t *read_file(const char *path, uint32_t *size);
int inject_params(uint8_t *payload, uint32_t payload_size,
                  const payload_params_t *params);

#endif // UTIL_H
