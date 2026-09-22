#include "patcher.h"
#include "image.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <capstone/capstone.h>

#define MAX_ANALYSIS_DEPTH 32
#define MAX_FUNCTION_SEARCH 0x20000u

typedef struct {
    uint32_t value;
    unsigned mask;
} reg_value_t;

typedef struct {
    csh handle;
    cs_insn *insn;
    size_t count;
    uint32_t base;
    uint32_t size;
    int thumb;
    const uint8_t *data;
} arm_analysis_t;

static reg_value_t reg_unknown(void)
{
    reg_value_t v = { 0, 0 };
    return v;
}

static reg_value_t reg_full(uint32_t value)
{
    reg_value_t v = { value, 3 };
    return v;
}

static int reg_index(arm_reg reg)
{
    switch (reg) {
    case ARM_REG_R0:  return 0;
    case ARM_REG_R1:  return 1;
    case ARM_REG_R2:  return 2;
    case ARM_REG_R3:  return 3;
    case ARM_REG_R4:  return 4;
    case ARM_REG_R5:  return 5;
    case ARM_REG_R6:  return 6;
    case ARM_REG_R7:  return 7;
    case ARM_REG_R8:  return 8;
    case ARM_REG_R9:  return 9;
    case ARM_REG_R10: return 10;
    case ARM_REG_R11: return 11;
    case ARM_REG_R12: return 12;
    case ARM_REG_SP:  return 13;
    case ARM_REG_LR:  return 14;
    case ARM_REG_PC:  return 15;
    default:          return -1;
    }
}

static int value_is_full(reg_value_t v)
{
    return v.mask == 3;
}

static uint32_t arm_pc(const arm_analysis_t *a, const cs_insn *insn)
{
    uint32_t pc = (uint32_t)insn->address + (a->thumb ? 4u : 8u);
    return pc & ~3u;
}

static int read_u32_va(const arm_analysis_t *a, uint32_t va, uint32_t *out)
{
    uint32_t off;

    if (va < a->base)
        return -1;
    off = va - a->base;
    if (off > a->size || a->size - off < sizeof(uint32_t))
        return -1;

    memcpy(out, a->data + off, sizeof(*out));
    return 0;
}

static int ptr_in_image(const arm_analysis_t *a, uint32_t va, int thumb)
{
    if (thumb)
        va &= ~1u;
    return va >= a->base && va < a->base + a->size;
}

static int is_literal_load(const cs_insn *insn)
{
    const cs_arm *arm;

    if (!insn->detail)
        return 0;
    arm = &insn->detail->arm;
    if (arm->op_count < 2 || arm->operands[1].type != ARM_OP_MEM)
        return 0;

    if (arm->operands[1].mem.base != ARM_REG_PC)
        return 0;

    switch (insn->id) {
    case ARM_INS_LDR:
    case ARM_INS_LDRB:
    case ARM_INS_LDRH:
    case ARM_INS_LDRSB:
    case ARM_INS_LDRSH:
        return 1;
    default:
        return 0;
    }
}

/* Resolve the value loaded by a PC-relative literal load. */
static int literal_value(const arm_analysis_t *a, const cs_insn *insn, uint32_t *out)
{
    const cs_arm_op *op;
    uint32_t pool;

    if (!is_literal_load(insn))
        return -1;

    op = &insn->detail->arm.operands[1];
    pool = arm_pc(a, insn) + (int32_t)op->mem.disp;
    if (read_u32_va(a, pool, out) != 0)
        return -1;

    return 0;
}

/* Find a reference to a value rather than the literal-pool slot itself. */
static int instruction_refers_to(const arm_analysis_t *a, const cs_insn *insn,
                                 uint32_t target_va)
{
    uint32_t value;

    if (literal_value(a, insn, &value) == 0 && value == target_va)
        return 1;

    return 0;
}

static const uint8_t *find_string(const uint8_t *data, uint32_t size, const char *str)
{
    uint32_t str_len = (uint32_t)strlen(str);

    if (!str_len || str_len > size)
        return NULL;

    for (uint32_t i = 0; i + str_len <= size; i++) {
        if (memcmp(data + i, str, str_len) == 0)
            return data + i;
    }

    return NULL;
}

static int open_analysis(arm_analysis_t *a, const uint8_t *data, uint32_t size,
                         uint32_t base, int thumb)
{
    cs_mode mode = thumb ? CS_MODE_THUMB : CS_MODE_ARM;

    memset(a, 0, sizeof(*a));
    if (cs_open(CS_ARCH_ARM, mode, &a->handle) != CS_ERR_OK)
        return -1;

    if (cs_option(a->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&a->handle);
        return -1;
    }

    a->count = cs_disasm(a->handle, data, size, base, 0, &a->insn);
    if (!a->count) {
        cs_close(&a->handle);
        memset(a, 0, sizeof(*a));
        return -1;
    }

    a->data = data;
    a->size = size;
    a->base = base;
    a->thumb = thumb;
    return 0;
}

static void close_analysis(arm_analysis_t *a)
{
    if (a->insn)
        cs_free(a->insn, a->count);
    if (a->handle)
        cs_close(&a->handle);
    memset(a, 0, sizeof(*a));
}

static int is_prologue(const cs_insn *insn)
{
    if (!insn)
        return 0;

    if (insn->id == ARM_INS_PUSH)
        return 1;

    if (!strncmp(insn->mnemonic, "stmdb", 5) ||
        !strncmp(insn->mnemonic, "stmfd", 5))
        return 1;

    return 0;
}

static int is_pop(const cs_insn *insn)
{
    return insn && (insn->id == ARM_INS_POP || !strcmp(insn->mnemonic, "pop"));
}

static int is_return(const cs_insn *insn)
{
    const cs_arm *arm;

    if (!insn)
        return 0;
    if (is_pop(insn))
        return 1;
    if (insn->id != ARM_INS_BX || !insn->detail)
        return 0;

    arm = &insn->detail->arm;
    return arm->op_count >= 1 && arm->operands[0].type == ARM_OP_REG &&
           arm->operands[0].reg == ARM_REG_LR;
}

static int is_block_terminator(const cs_insn *insn)
{
    if (!insn)
        return 1;

    if (is_return(insn))
        return 1;

    switch (insn->id) {
    case ARM_INS_B:
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        return 1;
    default:
        return 0;
    }
}

static int direct_call_target(const cs_insn *insn, uint32_t *target)
{
    const cs_arm *arm;

    if (!insn->detail)
        return -1;
    if (insn->id != ARM_INS_BL && insn->id != ARM_INS_BLX)
        return -1;

    arm = &insn->detail->arm;
    if (!arm->op_count || arm->operands[0].type != ARM_OP_IMM)
        return -1;

    *target = (uint32_t)arm->operands[0].imm;
    return 0;
}

static int destination_reg(const cs_insn *insn)
{
    const cs_arm *arm;

    if (!insn->detail || !insn->detail->arm.op_count)
        return -1;

    switch (insn->id) {
    case ARM_INS_MOV:
    case ARM_INS_MOVW:
    case ARM_INS_MOVT:
    case ARM_INS_LDR:
    case ARM_INS_LDRB:
    case ARM_INS_LDRH:
    case ARM_INS_LDRSB:
    case ARM_INS_LDRSH:
    case ARM_INS_ADD:
    case ARM_INS_SUB:
    case ARM_INS_ADR:
        break;
    default:
        return -1;
    }

    arm = &insn->detail->arm;
    if (arm->operands[0].type != ARM_OP_REG)
        return -1;
    return reg_index(arm->operands[0].reg);
}

static int instruction_writes_reg(const cs_insn *insn, int reg)
{
    return destination_reg(insn) == reg;
}

static int call_clobbers_reg(const cs_insn *insn, int reg)
{
    return (insn->id == ARM_INS_BL || insn->id == ARM_INS_BLX) && reg >= 0 && reg <= 3;
}

static reg_value_t resolve_reg_before(const arm_analysis_t *a, size_t begin, size_t at,
                                      int reg, unsigned depth);

static int previous_write(const arm_analysis_t *a, size_t begin, size_t at, int reg,
                          size_t *write_idx)
{
    while (at > begin) {
        at--;
        if (call_clobbers_reg(&a->insn[at], reg))
            return -2;
        if (instruction_writes_reg(&a->insn[at], reg)) {
            *write_idx = at;
            return 0;
        }
    }

    return -1;
}

static reg_value_t resolve_movw_movt(const arm_analysis_t *a, size_t begin,
                                     size_t idx, int reg, int want_high, unsigned depth)
{
    reg_value_t result = reg_unknown();
    size_t i = idx;

    if (depth > MAX_ANALYSIS_DEPTH)
        return result;

    if (want_high) {
        result.value = ((uint32_t)a->insn[idx].detail->arm.operands[1].imm & 0xffffu) << 16;
        result.mask = 2;
    } else {
        result.value = (uint32_t)a->insn[idx].detail->arm.operands[1].imm & 0xffffu;
        result.mask = 1;
    }

    while (i > begin) {
        i--;
        if (call_clobbers_reg(&a->insn[i], reg))
            break;
        if (!instruction_writes_reg(&a->insn[i], reg))
            continue;

        if (want_high && a->insn[i].id == ARM_INS_MOVW) {
            result.value = (result.value & 0xffff0000u) |
                           ((uint32_t)a->insn[i].detail->arm.operands[1].imm & 0xffffu);
            result.mask |= 1;
        } else if (!want_high && a->insn[i].id == ARM_INS_MOVT) {
            result.value = (result.value & 0xffffu) |
                           (((uint32_t)a->insn[i].detail->arm.operands[1].imm & 0xffffu) << 16);
            result.mask |= 2;
        }
        break;
    }

    return result;
}

static reg_value_t resolve_definition(const arm_analysis_t *a, size_t begin, size_t idx,
                                      int reg, unsigned depth)
{
    const cs_insn *insn = &a->insn[idx];
    const cs_arm *arm = &insn->detail->arm;
    reg_value_t result = reg_unknown();

    if (depth > MAX_ANALYSIS_DEPTH || arm->op_count < 2)
        return result;

    switch (insn->id) {
    case ARM_INS_MOV:
        if (arm->operands[1].type == ARM_OP_IMM)
            return reg_full((uint32_t)arm->operands[1].imm);
        if (arm->operands[1].type == ARM_OP_REG) {
            int src = reg_index(arm->operands[1].reg);
            if (src >= 0)
                return resolve_reg_before(a, begin, idx, src, depth + 1);
        }
        break;

    case ARM_INS_MOVW:
        if (arm->operands[1].type == ARM_OP_IMM)
            return resolve_movw_movt(a, begin, idx, reg, 0, depth + 1);
        break;

    case ARM_INS_MOVT:
        if (arm->operands[1].type == ARM_OP_IMM)
            return resolve_movw_movt(a, begin, idx, reg, 1, depth + 1);
        break;

    case ARM_INS_ADR:
        if (arm->operands[1].type == ARM_OP_IMM)
            return reg_full((uint32_t)arm->operands[1].imm);
        break;

    case ARM_INS_ADD:
    case ARM_INS_SUB: {
        reg_value_t left, right;
        int src;
        int is_add = insn->id == ARM_INS_ADD;

        if (arm->op_count < 3 || arm->operands[1].type != ARM_OP_REG)
            break;
        src = reg_index(arm->operands[1].reg);
        if (src < 0)
            break;
        left = resolve_reg_before(a, begin, idx, src, depth + 1);
        if (!value_is_full(left))
            break;

        if (arm->operands[2].type == ARM_OP_IMM) {
            int32_t delta = (int32_t)arm->operands[2].imm;
            result = reg_full(is_add ? left.value + delta : left.value - delta);
            return result;
        }

        if (arm->operands[2].type == ARM_OP_REG) {
            src = reg_index(arm->operands[2].reg);
            if (src < 0)
                break;
            right = resolve_reg_before(a, begin, idx, src, depth + 1);
            if (value_is_full(right))
                return reg_full(is_add ? left.value + right.value : left.value - right.value);
        }
        break;
    }

    case ARM_INS_LDR:
    case ARM_INS_LDRB:
    case ARM_INS_LDRH:
    case ARM_INS_LDRSB:
    case ARM_INS_LDRSH: {
        const cs_arm_op *mem;
        reg_value_t base_value;
        int base_reg;
        uint32_t address;
        uint32_t loaded;

        if (arm->operands[1].type != ARM_OP_MEM)
            break;
        mem = &arm->operands[1];

        if (mem->mem.base == ARM_REG_PC) {
            if (literal_value(a, insn, &loaded) == 0)
                return reg_full(loaded);
            break;
        }

        base_reg = reg_index(mem->mem.base);
        if (base_reg < 0)
            break;
        base_value = resolve_reg_before(a, begin, idx, base_reg, depth + 1);
        if (!value_is_full(base_value))
            break;

        address = base_value.value + (int32_t)mem->mem.disp;
        if (mem->mem.index != ARM_REG_INVALID) {
            int index_reg = reg_index(mem->mem.index);
            reg_value_t index_value;
            if (index_reg < 0)
                break;
            index_value = resolve_reg_before(a, begin, idx, index_reg, depth + 1);
            if (!value_is_full(index_value))
                break;
            address += index_value.value;
        }

        if (read_u32_va(a, address, &loaded) == 0)
            return reg_full(loaded);
        break;
    }

    default:
        break;
    }

    return result;
}

static reg_value_t resolve_reg_before(const arm_analysis_t *a, size_t begin, size_t at,
                                      int reg, unsigned depth)
{
    size_t idx;
    int ret;

    if (reg < 0 || depth > MAX_ANALYSIS_DEPTH)
        return reg_unknown();

    ret = previous_write(a, begin, at, reg, &idx);
    if (ret != 0)
        return reg_unknown();

    return resolve_definition(a, begin, idx, reg, depth + 1);
}

static int find_reference(const arm_analysis_t *a, uint32_t target_va, size_t *idx)
{
    for (size_t i = 0; i < a->count; i++) {
        if (instruction_refers_to(a, &a->insn[i], target_va)) {
            *idx = i;
            return 0;
        }
    }
    return -1;
}

static int find_function_range(const arm_analysis_t *a, size_t ref_idx,
                              size_t *begin, size_t *end)
{
    size_t start = ref_idx;
    size_t stop;
    uint32_t ref_va = (uint32_t)a->insn[ref_idx].address;

    while (start > 0) {
        start--;
        if (is_prologue(&a->insn[start]))
            break;
        if (ref_va - (uint32_t)a->insn[start].address > MAX_FUNCTION_SEARCH)
            break;
    }

    stop = ref_idx + 1;
    while (stop < a->count) {
        if (is_return(&a->insn[stop])) {
            stop++;
            break;
        }
        if (stop > ref_idx &&
            (uint32_t)a->insn[stop].address - ref_va > MAX_FUNCTION_SEARCH)
            break;
        stop++;
    }

    *begin = start;
    *end = stop;
    return 0;
}

static uint32_t function_address(const arm_analysis_t *a, size_t begin)
{
    return (uint32_t)a->insn[begin].address;
}

static int find_string_function(const arm_analysis_t *a, uint32_t str_va,
                               size_t *begin, size_t *end, size_t *ref_idx)
{
    size_t ref;

    if (find_reference(a, str_va, &ref) != 0)
        return -1;
    if (find_function_range(a, ref, begin, end) != 0)
        return -1;

    if (ref_idx)
        *ref_idx = ref;
    return 0;
}

static int block_has_pattern(const arm_analysis_t *a, size_t begin, size_t end,
                             size_t *best_begin, size_t *best_end)
{
    size_t block_start = begin;
    size_t best_score = 0;
    size_t best_lit = 0;
    size_t best_blx = 0;

    for (size_t i = begin; i < end; i++) {
        if (is_block_terminator(&a->insn[i]) || i + 1 == end) {
            size_t block_end = is_block_terminator(&a->insn[i]) ? i + 1 : end;
            size_t lits = 0;
            size_t blxs = 0;

            for (size_t j = block_start; j < block_end; j++) {
                if (is_literal_load(&a->insn[j]))
                    lits++;
                if (a->insn[j].id == ARM_INS_BLX &&
                    a->insn[j].detail &&
                    a->insn[j].detail->arm.op_count &&
                    a->insn[j].detail->arm.operands[0].type == ARM_OP_IMM)
                    blxs++;
            }

            if (lits >= 2 && blxs >= 4) {
                *best_begin = block_start;
                *best_end = block_end;
                return 0;
            }

            size_t score = lits * 8 + blxs;
            if (score > best_score ||
                (score == best_score && blxs > best_blx) ||
                (score == best_score && blxs == best_blx && lits > best_lit)) {
                best_score = score;
                best_lit = lits;
                best_blx = blxs;
                *best_begin = block_start;
                *best_end = block_end;
            }

            block_start = i + 1;
        }
    }

    return (best_score >= 12 && best_lit >= 2 && best_blx >= 2) ? 0 : -1;
}

static int try_preloader_dl_ul_mode(const uint8_t *data, uint32_t size, uint32_t base,
                                    int thumb, uint32_t *ptr_dl, uint32_t *ptr_ul)
{
    const char *pat = "%s sync time %dms\n";
    const uint8_t *found = find_string(data, size, pat);
    arm_analysis_t a;

    if (!found)
        return -1;
    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    uint32_t str_va = base + (uint32_t)(found - data);
    size_t ref_idx, begin, end;
    if (find_string_function(&a, str_va, &begin, &end, &ref_idx) != 0) {
        close_analysis(&a);
        return -1;
    }

    for (size_t i = begin; i < end; i++) {
        const cs_arm *arm;
        int r;
        reg_value_t array;
        uint32_t dl, ul;

        if (a.insn[i].id != ARM_INS_LDM || !a.insn[i].detail)
            continue;
        arm = &a.insn[i].detail->arm;
        if (!arm->op_count || arm->operands[0].type != ARM_OP_REG)
            continue;

        r = reg_index(arm->operands[0].reg);
        if (r < 0)
            continue;
        array = resolve_reg_before(&a, begin, i, r, 0);
        if (!value_is_full(array))
            continue;
        if (read_u32_va(&a, array.value, &dl) != 0 ||
            read_u32_va(&a, array.value + 4, &ul) != 0)
            continue;
        if (!ptr_in_image(&a, dl, 1) || !ptr_in_image(&a, ul, 1))
            continue;
        if (!(dl & 1) || !(ul & 1))
            continue;

        *ptr_dl = dl;
        *ptr_ul = ul;
        close_analysis(&a);
        return 0;
    }

    (void)ref_idx;
    close_analysis(&a);
    return -1;
}

int extract_preloader_dl_ul(const uint8_t *data, uint32_t size, uint32_t base,
                            uint32_t *ptr_dl, uint32_t *ptr_ul)
{
    if (try_preloader_dl_ul_mode(data, size, base, 1, ptr_dl, ptr_ul) == 0)
        return 0;
    return try_preloader_dl_ul_mode(data, size, base, 0, ptr_dl, ptr_ul);
}

static int try_lk_base_mode(const uint8_t *data, uint32_t size, uint32_t base,
                            int thumb, uint32_t *lk_base)
{
    const char *patterns[] = {
        "UBOOT",
        "%s Second Bootloader Load Failed",
    };
    arm_analysis_t a;

    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]); p++) {
        const uint8_t *found = find_string(data, size, patterns[p]);
        if (!found)
            continue;

        uint32_t str_va = base + (uint32_t)(found - data);
        for (size_t ref = 0; ref < a.count; ref++) {
            if (!instruction_refers_to(&a, &a.insn[ref], str_va))
                continue;

            size_t begin, end;
            if (find_function_range(&a, ref, &begin, &end) != 0)
                continue;

            reg_value_t r3 = resolve_reg_before(&a, begin, ref, 3, 0);
            if (value_is_full(r3) && r3.value >= 0x80000000u) {
                *lk_base = r3.value;
                close_analysis(&a);
                return 0;
            }

            (void)end;
        }
    }

    close_analysis(&a);
    return -1;
}

int extract_lk_base(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *lk_base)
{
    if (try_lk_base_mode(data, size, base, 1, lk_base) == 0)
        return 0;
    return try_lk_base_mode(data, size, base, 0, lk_base);
}

static int try_bldr_jump_mode(const uint8_t *data, uint32_t size, uint32_t base,
                              int thumb, uint32_t *bldr_jump, uint32_t *da_addr)
{
    const char *pat = "%s usbdl_jump_da: %x\n";
    const uint8_t *found = find_string(data, size, pat);
    arm_analysis_t a;
    size_t ref_idx, begin, end, block_begin, block_end;

    if (!found)
        return -1;
    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    uint32_t str_va = base + (uint32_t)(found - data);
    if (find_string_function(&a, str_va, &begin, &end, &ref_idx) != 0) {
        close_analysis(&a);
        return -1;
    }
    if (block_has_pattern(&a, begin, end, &block_begin, &block_end) != 0) {
        close_analysis(&a);
        return -1;
    }

    uint32_t last_target = 0;
    for (size_t i = block_begin; i < block_end; i++) {
        uint32_t target;
        if (direct_call_target(&a.insn[i], &target) == 0 && a.insn[i].id == ARM_INS_BLX)
            last_target = target;
    }
    if (!last_target)
        for (size_t i = block_begin; i < block_end; i++) {
            uint32_t target;
            if (direct_call_target(&a.insn[i], &target) == 0)
                last_target = target;
        }

    if (!last_target || !ptr_in_image(&a, last_target, 1)) {
        close_analysis(&a);
        return -1;
    }

    uint32_t da = 0;
    for (size_t i = block_begin; i < block_end; i++) {
        uint32_t value;
        if (literal_value(&a, &a.insn[i], &value) == 0 &&
            value >= 0x40000000u && !(value & 0xfffu)) {
            da = value;
            break;
        }
    }

    if (!da) {
        for (size_t i = begin; i < end; i++) {
            uint32_t value;
            if (literal_value(&a, &a.insn[i], &value) == 0 &&
                value >= 0x40000000u && !(value & 0xfffu)) {
                da = value;
                break;
            }
        }
    }

    if (!da) {
        close_analysis(&a);
        return -1;
    }

    *bldr_jump = last_target | 1u;
    *da_addr = da;
    (void)ref_idx;
    close_analysis(&a);
    return 0;
}

int extract_bldr_jump(const uint8_t *data, uint32_t size, uint32_t base,
                      uint32_t *bldr_jump, uint32_t *da_addr)
{
    if (try_bldr_jump_mode(data, size, base, 1, bldr_jump, da_addr) == 0)
        return 0;
    return try_bldr_jump_mode(data, size, base, 0, bldr_jump, da_addr);
}

static int try_function_by_string_mode(const uint8_t *data, uint32_t size, uint32_t base,
                                       int thumb, const char *pat, uint32_t *addr)
{
    const uint8_t *found = find_string(data, size, pat);
    arm_analysis_t a;
    size_t begin, end, ref_idx;

    if (!found)
        return -1;
    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    uint32_t str_va = base + (uint32_t)(found - data);
    if (find_string_function(&a, str_va, &begin, &end, &ref_idx) != 0) {
        close_analysis(&a);
        return -1;
    }

    *addr = function_address(&a, begin);
    (void)end;
    (void)ref_idx;
    close_analysis(&a);
    return 0;
}

int extract_mt_part_get_partition(const uint8_t *data, uint32_t size, uint32_t base,
                                  uint32_t *addr)
{
    if (try_function_by_string_mode(data, size, base, 1,
                                    "mt_part_get_partition", addr) == 0)
        return 0;
    return try_function_by_string_mode(data, size, base, 0,
                                       "mt_part_get_partition", addr);
}

int extract_get_part(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *addr)
{
    if (try_function_by_string_mode(data, size, base, 1, "get_part", addr) == 0)
        return 0;
    return try_function_by_string_mode(data, size, base, 0, "get_part", addr);
}

static int try_mt_part_generic_read_mode(const uint8_t *data, uint32_t size, uint32_t base,
                                         int thumb, uint32_t *addr)
{
    const char *patterns[] = {
        "[mt_part_register_device]\n",
        "[mt_part_register_device]",
    };
    arm_analysis_t a;

    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]); p++) {
        const uint8_t *found = find_string(data, size, patterns[p]);
        if (!found)
            continue;

        uint32_t str_va = base + (uint32_t)(found - data);
        size_t ref;
        if (find_reference(&a, str_va, &ref) != 0)
            continue;

        size_t begin, end;
        if (find_function_range(&a, ref, &begin, &end) != 0)
            continue;

        size_t block_begin = begin;
        for (size_t i = begin; i < end; i++) {
            if (is_block_terminator(&a.insn[i]) || i + 1 == end) {
                size_t block_end = is_block_terminator(&a.insn[i]) ? i + 1 : end;

                if (block_end - block_begin < 10) {
                    for (size_t j = block_begin; j < block_end; j++) {
                        const cs_arm *arm;
                        int src;
                        reg_value_t value;

                        if (a.insn[j].id != ARM_INS_STR || !a.insn[j].detail)
                            continue;
                        arm = &a.insn[j].detail->arm;
                        if (arm->op_count < 2 || arm->operands[0].type != ARM_OP_REG ||
                            arm->operands[1].type != ARM_OP_MEM ||
                            arm->operands[1].mem.disp != 0x10)
                            continue;

                        src = reg_index(arm->operands[0].reg);
                        if (src < 0)
                            continue;
                        value = resolve_reg_before(&a, block_begin, j, src, 0);
                        if (!value_is_full(value))
                            continue;
                        if (!ptr_in_image(&a, value.value, 1))
                            continue;

                        *addr = value.value;
                        close_analysis(&a);
                        return 0;
                    }
                }

                block_begin = i + 1;
            }
        }
    }

    close_analysis(&a);
    return -1;
}

int extract_mt_part_generic_read(const uint8_t *data, uint32_t size, uint32_t base,
                                 uint32_t *addr)
{
    if (try_mt_part_generic_read_mode(data, size, base, 1, addr) == 0)
        return 0;
    return try_mt_part_generic_read_mode(data, size, base, 0, addr);
}

/*
 * Analyze the actual code image, not the GFH container.  This mirrors the
 * upstream da-patcher flow: preloader files are sliced to their executable
 * content and the analyzer VA is load_addr + jump_offset.
 *
 * `base_hint` is retained for raw binaries which have no GFH header.
 */
int analyze_preloader(const uint8_t *data, uint32_t size, uint32_t base_hint,
                      uint32_t *ptr_dl, uint32_t *ptr_ul,
                      uint32_t *bldr_jump, uint32_t *da_addr,
                      uint32_t *lk_base)
{
    uint32_t load_addr = 0;
    uint32_t jump_offset = 0;
    uint32_t content_offset = 0;
    uint32_t content_size = size;
    uint32_t base = base_hint;
    const uint8_t *content = data;

    if (image_parse_preloader(data, size, &load_addr, &jump_offset,
                              &content_offset, &content_size) != 0)
        return -1;

    if (content_offset > size)
        return -1;
    if (content_size > size - content_offset)
        content_size = size - content_offset;

    content = data + content_offset;
    if (load_addr)
        base = load_addr + jump_offset;

    if (extract_preloader_dl_ul(content, content_size, base, ptr_dl, ptr_ul) != 0)
        return -1;
    if (extract_bldr_jump(content, content_size, base, bldr_jump, da_addr) != 0)
        return -1;

    /* LK base is useful for LK mode but isn't required by Preloader RPC. */
    if (extract_lk_base(content, content_size, base, lk_base) != 0)
        *lk_base = 0;

    return 0;
}
