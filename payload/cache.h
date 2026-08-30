#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

void flush_dcache(uint32_t start_addr, uint32_t size);
void flush_icache(void);

#endif // CACHE_H
