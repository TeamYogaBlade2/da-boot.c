#include "bump_alloc.h"
#include <stddef.h>

static uint8_t *g_heap_ptr = NULL;
static uint32_t g_heap_remaining = 0;

void bump_init(void *start, uint32_t size) {
    g_heap_ptr = (uint8_t*)start;
    g_heap_remaining = size;
}

void *bump_alloc(uint32_t size) {
    // 8バイトアラインメント
    size = (size + 7) & ~7;
    if (size > g_heap_remaining) return NULL;
    void *p = g_heap_ptr;
    g_heap_ptr += size;
    g_heap_remaining -= size;
    return p;
}

void bump_free(void *ptr) {
    // no-op
    (void)ptr;
}

uint32_t bump_remaining(void) {
    return g_heap_remaining;
}
