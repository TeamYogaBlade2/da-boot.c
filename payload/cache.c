#include "cache.h"

#define CACHE_LINE_SIZE 64

void flush_dcache(uint32_t start_addr, uint32_t size) {
    start_addr &= ~(CACHE_LINE_SIZE - 1);
    uint32_t end_addr = (start_addr + size + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1);

    for (uint32_t addr = start_addr; addr < end_addr; addr += CACHE_LINE_SIZE) {
        asm volatile("mcr p15, 0, %0, c7, c14, 1" :: "r"(addr));
    }
    asm volatile("dsb");
}

void flush_icache(void) {
    uint32_t zero = 0;
    // ICIALLU
    asm volatile("mcr p15, 0, %0, c7, c5, 0" :: "r"(zero));
    // BPIALL
    asm volatile("mcr p15, 0, %0, c7, c5, 6" :: "r"(zero));
    asm volatile("dsb");
    asm volatile("isb");
}
