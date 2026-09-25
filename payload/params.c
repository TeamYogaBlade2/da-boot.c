#include "da_params.h"
#include <stddef.h>

static int align_up8_u32(uint32_t value, uint32_t *aligned) {
    if (!aligned || value > UINT32_MAX - 7u)
        return -1;

    *aligned = (value + 7u) & ~7u;
    return 0;
}

int find_unused_range(const payload_params_t *p, uint32_t size, mem_range_t *out) {
    uint32_t aligned_size;
    uint32_t addr;

    if (!p || !out || size == 0 || p->memory.start > p->memory.end ||
        align_up8_u32(size, &aligned_size) != 0)
        return -1;

    addr = p->memory.start;

    while (addr <= p->memory.end) {
        uint32_t end;

        if (aligned_size > p->memory.end - addr)
            break;
        end = addr + aligned_size;

        int bad = 0;
        for (int i = 0; i < MAX_BLACKLIST; i++) {
            if (p->blacklist[i].mode != BLACKLIST_NONE) {
                uint32_t r_start = p->blacklist[i].range.start;
                uint32_t r_end = p->blacklist[i].range.end;
                if (addr < r_end && end > r_start) {
                    if (align_up8_u32(r_end, &addr) != 0 || addr <= r_start)
                        return -1;
                    bad = 1;
                    break;
                }
            }
        }
        if (!bad) {
            out->start = addr;
            out->end = end;
            return 0;
        }
    }
    return -1;
}

int blacklist_dl(payload_params_t *p, uint32_t start, uint32_t end) {
    if (!p || start >= end)
        return -1;

    for (int i = 0; i < MAX_BLACKLIST; i++) {
        /*
         * A range may have been reserved from the allocator as
         * BLACKLIST_RELOC before the host uploads data to it.  Once the
         * upload is complete, promote that reservation to BLACKLIST_DL
         * instead of consuming another blacklist slot.
         */
        if (p->blacklist[i].range.start == start &&
            p->blacklist[i].range.end == end) {
            if (p->blacklist[i].mode == BLACKLIST_DL)
                return 0;
            if (p->blacklist[i].mode == BLACKLIST_RELOC) {
                p->blacklist[i].mode = BLACKLIST_DL;
                return 0;
            }
        }
    }

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
    if (!p || start >= end)
        return -1;

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
