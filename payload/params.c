#include "da_params.h"
#include <stddef.h>

int find_unused_range(const payload_params_t *p, uint32_t size, mem_range_t *out) {
    uint32_t aligned_size = (size + 7) & ~7;
    uint32_t addr = p->memory.start;

    while (addr + aligned_size <= p->memory.end) {
        int bad = 0;
        for (int i = 0; i < MAX_BLACKLIST; i++) {
            if (p->blacklist[i].mode != BLACKLIST_NONE) {
                uint32_t r_start = p->blacklist[i].range.start;
                uint32_t r_end = p->blacklist[i].range.end;
                if (addr < r_end && (addr + aligned_size) > r_start) {
                    addr = (r_end + 7) & ~7;
                    bad = 1;
                    break;
                }
            }
        }
        if (!bad) {
            out->start = addr;
            out->end = addr + aligned_size;
            return 0;
        }
    }
    return -1;
}

int blacklist_dl(payload_params_t *p, uint32_t start, uint32_t end) {
    for (int i = 0; i < MAX_BLACKLIST; i++) {
        if (p->blacklist[i].mode == BLACKLIST_NONE) {
            p->blacklist[i].range.start = start;
            p->blacklist[i].range.end = end;
            p->blacklist[i].mode = BLACKLIST_DL;
            return 0;
        }
    }
    return -1;
}

int blacklist_reloc(payload_params_t *p, uint32_t start, uint32_t end) {
    for (int i = 0; i < MAX_BLACKLIST; i++) {
        if (p->blacklist[i].mode == BLACKLIST_NONE) {
            p->blacklist[i].range.start = start;
            p->blacklist[i].range.end = end;
            p->blacklist[i].mode = BLACKLIST_RELOC;
            return 0;
        }
    }
    return -1;
}
