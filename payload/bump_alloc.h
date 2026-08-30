#ifndef BUMP_ALLOC_H
#define BUMP_ALLOC_H

#include <stdint.h>

void bump_init(void *start, uint32_t size);
void *bump_alloc(uint32_t size);
void bump_free(void *ptr);
uint32_t bump_remaining(void);

#endif // BUMP_ALLOC_H
