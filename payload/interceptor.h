#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#include <stdint.h>

int interceptor_replace(uint32_t target, void *replacement);
int interceptor_revert(uint32_t target);
uint32_t interceptor_original(uint32_t target);

#endif // INTERCEPTOR_H
