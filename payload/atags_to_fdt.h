#ifndef ATAGS_TO_FDT_H
#define ATAGS_TO_FDT_H

#include <stdint.h>

int atags_to_fdt(void *atag_list, void *fdt, uint32_t total_space);

#endif
