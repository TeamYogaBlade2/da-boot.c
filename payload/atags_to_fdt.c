#include "atags_to_fdt.h"
#include "libc_min.h"

#include <stdint.h>
#include <stddef.h>

#define FDT_MAGIC            0xd00dfeedu
#define FDT_BEGIN_NODE       1u
#define FDT_END_NODE         2u
#define FDT_PROP             3u
#define FDT_NOP              4u
#define FDT_END              9u
#define FDT_HEADER_SIZE      40u
#define FDT_VERSION_MIN      17u

#define ATAG_NONE             0x00000000u
#define ATAG_CORE             0x54410001u
#define ATAG_MEM              0x54410002u
#define ATAG_SERIAL           0x54410006u
#define ATAG_CMDLINE          0x54410009u
#define ATAG_INITRD2          0x54420005u

#define ATAG_MAX_BYTES        (1024u * 1024u)
#define MAX_MEM_BANKS         16u
#define STRUCT_GAP             0x1000u
#define STRINGS_GAP            0x100u

struct tag_header {
    uint32_t size;
    uint32_t tag;
};

typedef struct {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_struct;
    uint32_t off_strings;
    uint32_t off_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_strings;
    uint32_t size_struct;
} fdt_header_t;

typedef struct {
    uint32_t start;
    uint32_t size;
} mem_bank_t;

typedef struct {
    const uint8_t *src;
    uint8_t *dst;
    uint32_t dst_total_space;
    uint32_t dst_struct;
    uint32_t dst_struct_pos;
    uint32_t dst_struct_limit;
    uint32_t dst_strings;
    uint32_t dst_strings_pos;
    uint32_t dst_strings_limit;
    uint32_t address_cells;
    uint32_t size_cells;
    mem_bank_t banks[MAX_MEM_BANKS];
    uint32_t bank_count;
    const char *cmdline;
    uint32_t initrd_start;
    uint32_t initrd_size;
    uint32_t serial_high;
    uint32_t serial_low;
    int have_cmdline;
    int have_initrd;
    int have_serial;
    int have_mem;
    int inserted_serial;
    int inserted_chosen;
    int inserted_memory;
} fdt_builder_t;

static uint32_t be32_get(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void be32_put(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint32_t align4(uint32_t value)
{
    return (value + 3u) & ~3u;
}

static void move_bytes(uint8_t *dst, const uint8_t *src, uint32_t size)
{
    if (dst == src || size == 0)
        return;

    if (dst < src) {
        for (uint32_t i = 0; i < size; i++)
            dst[i] = src[i];
    } else {
        for (uint32_t i = size; i > 0; i--)
            dst[i - 1] = src[i - 1];
    }
}

static uint32_t strlen_bounded(const char *s, uint32_t max)
{
    uint32_t len = 0;

    while (len < max && s[len] != '\0')
        len++;
    return len;
}

static int range_ok(uint32_t off, uint32_t size, uint32_t total)
{
    return off <= total && size <= total - off;
}

static int reserve_map_end(const uint8_t *fdt, const fdt_header_t *h,
                           uint32_t *end_out)
{
    uint32_t off = h->off_rsvmap;

    if (off < FDT_HEADER_SIZE || !range_ok(off, 16u, h->totalsize))
        return -1;

    for (;;) {
        uint32_t addr_hi, addr_lo, size_hi, size_lo;

        if (!range_ok(off, 16u, h->totalsize))
            return -1;

        addr_hi = be32_get(fdt + off);
        addr_lo = be32_get(fdt + off + 4u);
        size_hi = be32_get(fdt + off + 8u);
        size_lo = be32_get(fdt + off + 12u);
        off += 16u;

        if (!addr_hi && !addr_lo && !size_hi && !size_lo)
            break;
    }

    *end_out = off;
    return 0;
}

static int parse_header(const uint8_t *fdt, uint32_t available,
                        fdt_header_t *h)
{
    if (!fdt || !h || available < FDT_HEADER_SIZE)
        return -1;

    h->magic = be32_get(fdt);
    h->totalsize = be32_get(fdt + 4u);
    h->off_struct = be32_get(fdt + 8u);
    h->off_strings = be32_get(fdt + 12u);
    h->off_rsvmap = be32_get(fdt + 16u);
    h->version = be32_get(fdt + 20u);
    h->last_comp_version = be32_get(fdt + 24u);
    h->boot_cpuid_phys = be32_get(fdt + 28u);
    h->size_strings = be32_get(fdt + 32u);
    h->size_struct = be32_get(fdt + 36u);

    if (h->magic != FDT_MAGIC ||
        h->totalsize < FDT_HEADER_SIZE ||
        h->totalsize > available ||
        h->version < FDT_VERSION_MIN ||
        h->last_comp_version > h->version ||
        !range_ok(h->off_struct, h->size_struct, h->totalsize) ||
        !range_ok(h->off_strings, h->size_strings, h->totalsize) ||
        h->off_rsvmap < FDT_HEADER_SIZE)
        return -1;

    return 0;
}

static int src_string(const uint8_t *src, uint32_t off_strings,
                      uint32_t size_strings, uint32_t nameoff,
                      const char **name_out)
{
    const char *name;
    uint32_t len;

    if (nameoff >= size_strings)
        return -1;

    name = (const char *)(src + off_strings + nameoff);
    len = strlen_bounded(name, size_strings - nameoff);
    if (len == size_strings - nameoff)
        return -1;

    *name_out = name;
    return 0;
}

static int get_root_cell(const uint8_t *fdt, const fdt_header_t *h,
                         const char *wanted, uint32_t *value)
{
    uint32_t pos = 0;
    uint32_t depth = 0;

    while (pos + 4u <= h->size_struct) {
        uint32_t token = be32_get(fdt + h->off_struct + pos);
        pos += 4u;

        switch (token) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)(fdt + h->off_struct + pos);
            uint32_t len;

            if (pos >= h->size_struct)
                return -1;
            len = strlen_bounded(name, h->size_struct - pos);
            if (len == h->size_struct - pos)
                return -1;
            pos = align4(pos + len + 1u);
            depth++;
            break;
        }
        case FDT_END_NODE:
            if (!depth)
                return -1;
            depth--;
            break;
        case FDT_PROP: {
            uint32_t len, nameoff;
            const char *name;

            if (pos + 8u > h->size_struct)
                return -1;
            len = be32_get(fdt + h->off_struct + pos);
            nameoff = be32_get(fdt + h->off_struct + pos + 4u);
            pos += 8u;
            if (!range_ok(pos, len, h->size_struct) ||
                src_string(fdt, h->off_strings, h->size_strings, nameoff,
                           &name) != 0)
                return -1;
            if (depth == 1u && len == 4u && strcmp(name, wanted) == 0) {
                *value = be32_get(fdt + h->off_struct + pos);
                return 0;
            }
            pos = align4(pos + len);
            break;
        }
        case FDT_NOP:
            break;
        case FDT_END:
            return depth == 0u ? -1 : -1;
        default:
            return -1;
        }
    }

    return -1;
}

static int parse_atags(void *atag_list, fdt_builder_t *b)
{
    const uint8_t *p = (const uint8_t *)atag_list;
    uint32_t offset = 0;
    int have_core = 0;

    while (offset + 8u <= ATAG_MAX_BYTES) {
        struct tag_header h;
        uint32_t bytes;

        memcpy(&h, p + offset, sizeof(h));

        if (h.tag == ATAG_NONE)
            return have_core ? 0 : -1;
        if (h.size < 2u || h.size > (ATAG_MAX_BYTES - offset) / 4u)
            return -1;

        bytes = h.size * 4u;
        if (!have_core) {
            if (h.tag != ATAG_CORE || (h.size != 2u && h.size != 5u))
                return -1;
            have_core = 1;
        } else if (h.tag == ATAG_MEM && h.size >= 4u) {
            uint32_t start, size;

            memcpy(&start, p + offset + 8u, 4u);
            memcpy(&size, p + offset + 12u, 4u);
            if (size && b->bank_count < MAX_MEM_BANKS) {
                b->banks[b->bank_count].start = start;
                b->banks[b->bank_count].size = size;
                b->bank_count++;
                b->have_mem = 1;
            }
        } else if (h.tag == ATAG_INITRD2 && h.size >= 4u) {
            memcpy(&b->initrd_start, p + offset + 8u, 4u);
            memcpy(&b->initrd_size, p + offset + 12u, 4u);
            b->have_initrd = 1;
        } else if (h.tag == ATAG_SERIAL && h.size >= 4u) {
            memcpy(&b->serial_high, p + offset + 8u, 4u);
            memcpy(&b->serial_low, p + offset + 12u, 4u);
            b->have_serial = 1;
        } else if (h.tag == ATAG_CMDLINE && h.size >= 3u) {
            const char *cmdline = (const char *)(p + offset + 8u);
            uint32_t max = bytes - 8u;

            if (strlen_bounded(cmdline, max) == max)
                return -1;
            b->cmdline = cmdline;
            b->have_cmdline = 1;
        }

        offset += bytes;
    }

    return -1;
}

static int emit_word(fdt_builder_t *b, uint32_t value)
{
    if (b->dst_struct > b->dst_struct_limit ||
        b->dst_struct_pos > b->dst_struct_limit - b->dst_struct ||
        b->dst_struct_pos + 4u > b->dst_struct_limit - b->dst_struct)
        return -1;

    be32_put(b->dst + b->dst_struct + b->dst_struct_pos, value);
    b->dst_struct_pos += 4u;
    return 0;
}

static int emit_bytes(fdt_builder_t *b, const uint8_t *data, uint32_t size)
{
    if (b->dst_struct > b->dst_struct_limit ||
        b->dst_struct_pos > b->dst_struct_limit - b->dst_struct ||
        size > b->dst_struct_limit - b->dst_struct - b->dst_struct_pos)
        return -1;

    if (size)
        memcpy(b->dst + b->dst_struct + b->dst_struct_pos, data, size);
    b->dst_struct_pos += size;
    return 0;
}

static int emit_pad4(fdt_builder_t *b)
{
    static const uint8_t zero[4] = { 0 };
    uint32_t aligned = align4(b->dst_struct_pos);
    uint32_t pad = aligned - b->dst_struct_pos;

    return emit_bytes(b, zero, pad);
}

static int emit_node_begin(fdt_builder_t *b, const char *name)
{
    uint32_t len = (uint32_t)strlen(name) + 1u;

    if (emit_word(b, FDT_BEGIN_NODE) != 0 ||
        emit_bytes(b, (const uint8_t *)name, len) != 0 ||
        emit_pad4(b) != 0)
        return -1;
    return 0;
}

static uint32_t find_string_offset(const uint8_t *strings, uint32_t size,
                                   const char *wanted)
{
    uint32_t off = 0;

    while (off < size) {
        uint32_t len = strlen_bounded((const char *)(strings + off), size - off);
        if (len == size - off)
            return UINT32_MAX;
        if (strcmp((const char *)(strings + off), wanted) == 0)
            return off;
        off += len + 1u;
    }

    return UINT32_MAX;
}

static int ensure_string(fdt_builder_t *b, const char *name,
                         uint32_t *nameoff)
{
    uint8_t *strings = b->dst + b->dst_strings;
    uint32_t off = find_string_offset(strings, b->dst_strings_pos, name);
    uint32_t len;

    if (off != UINT32_MAX) {
        *nameoff = off;
        return 0;
    }

    len = (uint32_t)strlen(name) + 1u;
    if (b->dst_strings_pos > b->dst_strings_limit - b->dst_strings ||
        len > b->dst_strings_limit - b->dst_strings - b->dst_strings_pos)
        return -1;

    off = b->dst_strings_pos;
    memcpy(strings + off, name, len);
    b->dst_strings_pos += len;
    *nameoff = off;
    return 0;
}

static int emit_prop_raw(fdt_builder_t *b, const char *name,
                         const uint8_t *data, uint32_t len)
{
    uint32_t nameoff;

    if (ensure_string(b, name, &nameoff) != 0 ||
        emit_word(b, FDT_PROP) != 0 ||
        emit_word(b, len) != 0 ||
        emit_word(b, nameoff) != 0 ||
        emit_bytes(b, data, len) != 0 ||
        emit_pad4(b) != 0)
        return -1;
    return 0;
}

static int emit_prop_string(fdt_builder_t *b, const char *name,
                            const char *value)
{
    return emit_prop_raw(b, name, (const uint8_t *)value,
                         (uint32_t)strlen(value) + 1u);
}

static int emit_prop_cell(fdt_builder_t *b, const char *name, uint32_t value)
{
    uint8_t cell[4];

    be32_put(cell, value);
    return emit_prop_raw(b, name, cell, sizeof(cell));
}

static int emit_prop_reg(fdt_builder_t *b)
{
    uint8_t cells[MAX_MEM_BANKS * 16u];
    uint32_t pos = 0;

    if (!b->address_cells || b->address_cells > 2u ||
        !b->size_cells || b->size_cells > 2u)
        return -1;

    for (uint32_t i = 0; i < b->bank_count; i++) {
        if (b->address_cells == 2u) {
            be32_put(cells + pos, 0);
            pos += 4u;
        }
        be32_put(cells + pos, b->banks[i].start);
        pos += 4u;
        if (b->size_cells == 2u) {
            be32_put(cells + pos, 0);
            pos += 4u;
        }
        be32_put(cells + pos, b->banks[i].size);
        pos += 4u;
    }

    return emit_prop_raw(b, "reg", cells, pos);
}

static int insert_chosen_props(fdt_builder_t *b)
{
    if (b->have_cmdline &&
        emit_prop_string(b, "bootargs", b->cmdline) != 0)
        return -1;

    if (b->have_initrd) {
        uint32_t end = b->initrd_start + b->initrd_size;

        if (emit_prop_cell(b, "linux,initrd-start", b->initrd_start) != 0 ||
            emit_prop_cell(b, "linux,initrd-end", end) != 0)
            return -1;
    }

    return 0;
}

static int insert_root_serial(fdt_builder_t *b)
{
    static const char hex[] = "0123456789ABCDEF";
    char serial[17];
    uint32_t value;

    if (!b->have_serial || b->inserted_serial)
        return 0;

    value = b->serial_high;
    for (int i = 0; i < 8; i++) {
        serial[7 - i] = hex[value & 0xfu];
        value >>= 4;
    }
    value = b->serial_low;
    for (int i = 0; i < 8; i++) {
        serial[15 - i] = hex[value & 0xfu];
        value >>= 4;
    }
    serial[16] = '\0';

    if (emit_prop_string(b, "serial-number", serial) != 0)
        return -1;
    b->inserted_serial = 1;
    return 0;
}

static int should_skip_property(const fdt_builder_t *b, const char *name,
                               int in_root, int in_chosen, int in_memory)
{
    if (in_root && b->have_serial && strcmp(name, "serial-number") == 0)
        return 1;
    if (in_chosen && b->have_cmdline && strcmp(name, "bootargs") == 0)
        return 1;
    if (in_chosen && b->have_initrd &&
        (strcmp(name, "linux,initrd-start") == 0 ||
         strcmp(name, "linux,initrd-end") == 0))
        return 1;
    if (in_memory && b->have_mem && strcmp(name, "reg") == 0)
        return 1;
    return 0;
}

static int emit_existing_property(fdt_builder_t *b, const char *name,
                                  const uint8_t *data, uint32_t len)
{
    return emit_prop_raw(b, name, data, len);
}

static int convert_structure(fdt_builder_t *b,
                             uint32_t src_off_struct,
                             uint32_t src_size_struct,
                             uint32_t src_off_strings,
                             uint32_t src_size_strings)
{
    uint32_t pos = 0;
    uint32_t depth = 0;
    int in_chosen = 0;
    int in_memory = 0;

    while (pos + 4u <= src_size_struct) {
        uint32_t token = be32_get(b->src + src_off_struct + pos);
        pos += 4u;

        switch (token) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)(b->src + src_off_struct + pos);
            uint32_t len;

            if (pos >= src_size_struct)
                return -1;
            len = strlen_bounded(name, src_size_struct - pos);
            if (len == src_size_struct - pos)
                return -1;
            if (emit_node_begin(b, name) != 0)
                return -1;

            if (depth == 0u) {
                if (insert_root_serial(b) != 0)
                    return -1;
            } else if (depth == 1u && strcmp(name, "chosen") == 0) {
                in_chosen = 1;
                b->inserted_chosen = 1;
                if (insert_chosen_props(b) != 0)
                    return -1;
            } else if (depth == 1u && strcmp(name, "memory") == 0) {
                in_memory = 1;
                b->inserted_memory = 1;
                if (b->have_mem && emit_prop_reg(b) != 0)
                    return -1;
            }

            depth++;
            pos = align4(pos + len + 1u);
            break;
        }
        case FDT_END_NODE:
            if (!depth)
                return -1;
            depth--;
            if (depth == 0u) {
                if (in_chosen || in_memory) {
                    in_chosen = 0;
                    in_memory = 0;
                }
                if (b->have_serial && !b->inserted_serial &&
                    insert_root_serial(b) != 0)
                    return -1;
                if (!b->inserted_chosen &&
                    (b->have_cmdline || b->have_initrd)) {
                    if (emit_node_begin(b, "chosen") != 0 ||
                        insert_chosen_props(b) != 0 ||
                        emit_word(b, FDT_END_NODE) != 0)
                        return -1;
                    b->inserted_chosen = 1;
                }
                if (!b->inserted_memory && b->have_mem) {
                    if (emit_node_begin(b, "memory") != 0 ||
                        emit_prop_string(b, "device_type", "memory") != 0 ||
                        emit_prop_reg(b) != 0 ||
                        emit_word(b, FDT_END_NODE) != 0)
                        return -1;
                    b->inserted_memory = 1;
                }
            } else if (depth == 1u) {
                if (in_chosen)
                    in_chosen = 0;
                if (in_memory)
                    in_memory = 0;
            }
            if (emit_word(b, FDT_END_NODE) != 0)
                return -1;
            break;
        case FDT_PROP: {
            uint32_t len, nameoff;
            const char *name;

            if (pos + 8u > src_size_struct)
                return -1;
            len = be32_get(b->src + src_off_struct + pos);
            nameoff = be32_get(b->src + src_off_struct + pos + 4u);
            pos += 8u;
            if (!range_ok(pos, len, src_size_struct) ||
                src_string(b->src, src_off_strings, src_size_strings, nameoff,
                           &name) != 0)
                return -1;
            if (!should_skip_property(b, name, depth == 1u, in_chosen, in_memory)) {
                if (emit_existing_property(b, name,
                                            b->src + src_off_struct + pos,
                                            len) != 0)
                    return -1;
            }
            pos = align4(pos + len);
            break;
        }
        case FDT_NOP:
            if (emit_word(b, FDT_NOP) != 0)
                return -1;
            break;
        case FDT_END:
            if (depth != 0u || emit_word(b, FDT_END) != 0)
                return -1;
            return 0;
        default:
            return -1;
        }
    }

    return -1;
}

int atags_to_fdt(void *atag_list, void *fdt, uint32_t total_space)
{
    fdt_header_t h;
    fdt_builder_t b;
    uint32_t reserve_end;
    uint32_t source_off;
    uint32_t strings_tmp;
    uint32_t struct_off;
    uint32_t new_strings_off;
    uint32_t new_total;
    uint32_t address_cells = 1u;
    uint32_t size_cells = 1u;

    if (!atag_list || !fdt || total_space < 0x2000u)
        return -1;

    if (parse_atags(atag_list, &b) != 0)
        return -1;
    if (parse_header((const uint8_t *)fdt, total_space, &h) != 0)
        return -1;
    if (reserve_map_end((const uint8_t *)fdt, &h, &reserve_end) != 0)
        return -1;

    (void)get_root_cell((const uint8_t *)fdt, &h,
                        "#address-cells", &address_cells);
    (void)get_root_cell((const uint8_t *)fdt, &h,
                        "#size-cells", &size_cells);
    if (!address_cells || address_cells > 2u ||
        !size_cells || size_cells > 2u)
        return -1;

    if (h.totalsize > (UINT32_MAX - STRUCT_GAP) / 2u)
        return -1;
    source_off = align4(total_space - h.totalsize);
    if (source_off < reserve_end + STRUCT_GAP ||
        source_off + h.totalsize > total_space)
        return -1;

    strings_tmp = source_off;
    if (h.size_strings > strings_tmp ||
        strings_tmp - h.size_strings < STRINGS_GAP)
        return -1;
    strings_tmp = align4(strings_tmp - h.size_strings - STRINGS_GAP);
    struct_off = align4(reserve_end + 0x100u);
    if (struct_off >= strings_tmp ||
        h.size_strings > source_off - strings_tmp)
        return -1;

    move_bytes((uint8_t *)fdt + source_off, (const uint8_t *)fdt, h.totalsize);

    memset(&b, 0, sizeof(b));
    if (parse_atags(atag_list, &b) != 0)
        return -1;
    b.src = (const uint8_t *)fdt + source_off;
    b.dst = (uint8_t *)fdt;
    b.dst_total_space = total_space;
    b.dst_struct = struct_off;
    b.dst_struct_pos = 0;
    b.dst_struct_limit = strings_tmp;
    b.dst_strings = strings_tmp;
    b.dst_strings_pos = h.size_strings;
    b.dst_strings_limit = source_off;
    b.address_cells = address_cells;
    b.size_cells = size_cells;
    memcpy(b.dst + b.dst_strings, b.src + h.off_strings, h.size_strings);

    if (convert_structure(&b, h.off_struct, h.size_struct,
                          h.off_strings, h.size_strings) != 0)
        return -1;

    new_strings_off = align4(struct_off + b.dst_struct_pos);
    if (new_strings_off < struct_off ||
        new_strings_off > total_space ||
        b.dst_strings_pos > total_space - new_strings_off)
        return -1;

    move_bytes(b.dst + new_strings_off, b.dst + b.dst_strings,
               b.dst_strings_pos);
    new_total = align4(new_strings_off + b.dst_strings_pos);
    if (new_total > total_space)
        return -1;

    move_bytes(b.dst, b.src, FDT_HEADER_SIZE);
    be32_put(b.dst + 4u, new_total);
    be32_put(b.dst + 8u, struct_off);
    be32_put(b.dst + 12u, new_strings_off);
    be32_put(b.dst + 16u, h.off_rsvmap);
    be32_put(b.dst + 20u, h.version);
    be32_put(b.dst + 24u, h.last_comp_version);
    be32_put(b.dst + 28u, h.boot_cpuid_phys);
    be32_put(b.dst + 32u, b.dst_strings_pos);
    be32_put(b.dst + 36u, b.dst_struct_pos);
    return 0;
}
