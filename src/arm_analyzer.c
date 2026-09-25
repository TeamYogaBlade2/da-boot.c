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

static int destination_reg(const cs_insn *insn);

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

static uint32_t arm_register_pc(const arm_analysis_t *a, const cs_insn *insn)
{
    return (uint32_t)insn->address + (a->thumb ? 4u : 8u);
}

static uint32_t arm_literal_pc(const arm_analysis_t *a, const cs_insn *insn)
{
    uint32_t pc = arm_register_pc(a, insn);

    return a->thumb ? (pc & ~3u) : pc;
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
    pool = arm_literal_pc(a, insn) + (int32_t)op->mem.disp;
    if (read_u32_va(a, pool, out) != 0)
        return -1;

    return 0;
}

static reg_value_t resolve_reg_before(const arm_analysis_t *a, size_t begin, size_t at,
                                      int reg, unsigned depth);

static reg_value_t resolve_movw_movt(const arm_analysis_t *a, size_t begin,
                                     size_t idx, int reg, int want_high, unsigned depth);

static reg_value_t resolve_definition(const arm_analysis_t *a, size_t begin, size_t idx,
                                      int reg, unsigned depth);

static int resolve_operand_value(const arm_analysis_t *a, size_t begin, size_t at,
                                 const cs_arm_op *op, uint32_t *value)
{
    reg_value_t resolved;
    int reg;

    if (!op || !value)
        return -1;

    switch (op->type) {
    case ARM_OP_IMM:
        *value = (uint32_t)op->imm;
        return 0;

    case ARM_OP_REG:
        if (op->reg == ARM_REG_PC) {
            *value = arm_register_pc(a, &a->insn[at]);
            return 0;
        }

        reg = reg_index(op->reg);
        if (reg < 0)
            return -1;

        resolved = resolve_reg_before(a, begin, at, reg, 0);
        if (!value_is_full(resolved))
            return -1;

        *value = resolved.value;
        return 0;

    default:
        return -1;
    }
}

/* Find a reference to a value rather than the literal-pool slot itself. */
static int instruction_refers_to(const arm_analysis_t *a, const cs_insn *insn,
                                 uint32_t target_va)
{
    const cs_arm *arm;
    uint32_t value;

    if (literal_value(a, insn, &value) == 0 && value == target_va)
        return 1;

    if (!insn->detail)
        return 0;

    arm = &insn->detail->arm;

    /*
     * Thumb/ARM code frequently materializes a string address with
     * ADD/ADR instead of loading it from a literal pool.  In particular,
     *
     *     add r3, pc
     *
     * is the Thumb two-operand form of:
     *
     *     r3 = r3 + PC
     *
     * and therefore requires tracking the old value of the destination
     * register as well.
     */
    if (insn->id == ARM_INS_ADR) {
        if (arm->op_count >= 2 &&
            arm->operands[0].type == ARM_OP_REG &&
            arm->operands[1].type == ARM_OP_IMM &&
            (uint32_t)arm->operands[1].imm == target_va)
            return 1;
    }

    if (insn->id == ARM_INS_ADD || insn->id == ARM_INS_SUB) {
        uint32_t left, right, result;
        int is_add = insn->id == ARM_INS_ADD;

        if (arm->op_count == 2 &&
            arm->operands[0].type == ARM_OP_REG &&
            arm->operands[1].type == ARM_OP_REG &&
            arm->operands[1].reg == ARM_REG_PC) {
            int dst = reg_index(arm->operands[0].reg);

            if (dst >= 0) {
                reg_value_t old_dst =
                    resolve_reg_before(a, 0, (size_t)(insn - a->insn), dst, 0);
                if (value_is_full(old_dst)) {
                    result = old_dst.value + arm_register_pc(
                        a, &a->insn[(size_t)(insn - a->insn)]);
                    if (result == target_va)
                        return 1;
                }
            }
        } else if (arm->op_count >= 3 &&
                   arm->operands[0].type == ARM_OP_REG) {
            size_t at = (size_t)(insn - a->insn);

            if (arm->operands[1].type == ARM_OP_REG &&
                arm->operands[1].reg == ARM_REG_PC &&
                resolve_operand_value(a, 0, at, &arm->operands[2], &right) == 0) {
                left = arm_register_pc(a, insn);
                result = is_add ? left + right : left - right;
                if (result == target_va)
                    return 1;
            }

            if (arm->operands[2].type == ARM_OP_REG &&
                arm->operands[2].reg == ARM_REG_PC &&
                resolve_operand_value(a, 0, at, &arm->operands[1], &left) == 0) {
                right = arm_register_pc(a, insn);
                result = is_add ? left + right : left - right;
                if (result == target_va)
                    return 1;
            }
        }
    }

    /*
     * Use the same backward value resolver used for the DL/UL table.
     * This covers MOVW/MOVT as well as compiler-generated combinations
     * such as:
     *
     *     mov r3, pc
     *     add r3, #imm
     *
     * or:
     *
     *     movw r3, #lo
     *     movt r3, #hi
     *     add  r3, #delta
     */
    {
        size_t at = (size_t)(insn - a->insn);
        int dst = destination_reg(insn);

        if (dst >= 0) {
            reg_value_t resolved =
                resolve_definition(a, 0, at, dst, 0);

            if (value_is_full(resolved) && resolved.value == target_va)
                return 1;
        }
    }

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

static const uint8_t *find_string_from(const uint8_t *data, uint32_t size,
                                       const char *str, uint32_t start)
{
    uint32_t str_len = (uint32_t)strlen(str);

    if (!str_len || str_len > size || start > size - str_len)
        return NULL;

    for (uint32_t i = start; i + str_len <= size; i++) {
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
    if (cs_open(CS_ARCH_ARM, mode, &a->handle) != CS_ERR_OK) {
        fprintf(stderr, "[analyzer] cs_open failed (%s mode)\n",
                thumb ? "Thumb" : "ARM");
        return -1;
    }

    if (cs_option(a->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        fprintf(stderr, "[analyzer] cs_option(CS_OPT_DETAIL) failed (%s mode)\n",
                thumb ? "Thumb" : "ARM");
        cs_close(&a->handle);
        return -1;
    }

    /*
     * A MediaTek Preloader is not a single linear instruction stream:
     * code and literal/data regions are interleaved, and ARM/Thumb code
     * may coexist.  Without SKIPDATA, Capstone stops at the first byte
     * sequence which is invalid in the selected mode, potentially hiding
     * all later references.
     */
    if (cs_option(a->handle, CS_OPT_SKIPDATA, CS_OPT_ON) != CS_ERR_OK) {
        fprintf(stderr, "[analyzer] cs_option(CS_OPT_SKIPDATA) failed (%s mode)\n",
                thumb ? "Thumb" : "ARM");
        cs_close(&a->handle);
        return -1;
    }

    a->count = cs_disasm(a->handle, data, size, base, 0, &a->insn);
    if (!a->count) {
        fprintf(stderr,
                "[analyzer] disassembly failed: base=0x%08x size=0x%x mode=%s\n",
                base, size, thumb ? "Thumb" : "ARM");
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

/* Return the immediate target of a conditional/unconditional branch. */
static int branch_target(const cs_insn *insn, uint32_t *target)
{
    const cs_arm *arm;

    if (!insn || !insn->detail)
        return -1;

    switch (insn->id) {
    case ARM_INS_B:
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        break;
    default:
        return -1;
    }

    arm = &insn->detail->arm;
    for (unsigned i = 0; i < arm->op_count; i++) {
        if (arm->operands[i].type == ARM_OP_IMM) {
            *target = (uint32_t)arm->operands[i].imm;
            return 0;
        }
    }

    return -1;
}

static int call_target(const arm_analysis_t *a, size_t begin, size_t idx,
                       uint32_t *target)
{
    const cs_insn *insn = &a->insn[idx];
    const cs_arm *arm;

    if (!insn->detail)
        return -1;
    if (insn->id != ARM_INS_BL && insn->id != ARM_INS_BLX)
        return -1;

    arm = &insn->detail->arm;
    if (!arm->op_count || arm->operands[0].type != ARM_OP_IMM)
    {
        int reg;
        reg_value_t value;

        if (arm->operands[0].type != ARM_OP_REG)
            return -1;

        reg = reg_index(arm->operands[0].reg);
        if (reg < 0)
            return -1;

        value = resolve_reg_before(a, begin, idx, reg, 0);
        if (!value_is_full(value))
            return -1;

        *target = value.value;
        return 0;
    }

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
        if (arm->operands[1].type == ARM_OP_REG &&
            arm->operands[1].reg == ARM_REG_PC)
            return reg_full(arm_register_pc(a, insn));
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
        int src, dst;
        int is_add = insn->id == ARM_INS_ADD;

        if (arm->operands[0].type != ARM_OP_REG)
            break;

        dst = reg_index(arm->operands[0].reg);
        if (dst < 0)
            break;

        /*
         * Thumb two-operand register ADD/SUB has an implicit first source:
         *
         *     add r3, pc     -> r3 = r3 + PC
         *     add r0, r1     -> r0 = r0 + r1
         */
        if (arm->op_count == 2 &&
            arm->operands[1].type == ARM_OP_REG) {
            left = resolve_reg_before(a, begin, idx, dst, depth + 1);
            if (!value_is_full(left))
                break;

            if (arm->operands[1].reg == ARM_REG_PC) {
                right = reg_full(arm_register_pc(a, insn));
            } else {
                src = reg_index(arm->operands[1].reg);
                if (src < 0)
                    break;
                right = resolve_reg_before(a, begin, idx, src, depth + 1);
                if (!value_is_full(right))
                    break;
            }

            return reg_full(is_add ? left.value + right.value
                                   : left.value - right.value);
        }

        if (arm->op_count == 2 &&
            arm->operands[1].type == ARM_OP_IMM) {
            left = resolve_reg_before(a, begin, idx, dst, depth + 1);
            if (!value_is_full(left))
                break;

            return reg_full(is_add
                                ? left.value + (uint32_t)arm->operands[1].imm
                                : left.value - (uint32_t)arm->operands[1].imm);
        }

        if (arm->op_count < 3)
            break;

        if (arm->operands[1].type != ARM_OP_REG)
            break;

        if (arm->operands[1].reg == ARM_REG_PC)
            left = reg_full(arm_register_pc(a, insn));
        else {
            src = reg_index(arm->operands[1].reg);
            if (src < 0)
                break;
            left = resolve_reg_before(a, begin, idx, src, depth + 1);
            if (!value_is_full(left))
                break;
        }

        if (arm->operands[2].type == ARM_OP_IMM)
            return reg_full(is_add
                                ? left.value + (uint32_t)arm->operands[2].imm
                                : left.value - (uint32_t)arm->operands[2].imm);

        if (arm->operands[2].type == ARM_OP_REG) {
            src = reg_index(arm->operands[2].reg);
            if (src < 0)
                break;
            right = resolve_reg_before(a, begin, idx, src, depth + 1);
            if (!value_is_full(right))
                break;

            return reg_full(is_add
                                ? left.value + right.value
                                : left.value - right.value);
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
            fprintf(stderr,
                    "[analyzer] xref: 0x%08x -> 0x%08x (%s: %s %s)\n",
                    (uint32_t)a->insn[i].address,
                    target_va,
                    a->thumb ? "Thumb" : "ARM",
                    a->insn[i].mnemonic,
                    a->insn[i].op_str);
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

static int load_reg_from_mem(const cs_insn *insn, int base_reg, int32_t disp,
                             int *dst)
{
    const cs_arm *arm;

    if (!insn || !insn->detail || insn->id != ARM_INS_LDR)
        return 0;

    arm = &insn->detail->arm;
    if (arm->op_count < 2 ||
        arm->operands[0].type != ARM_OP_REG ||
        arm->operands[1].type != ARM_OP_MEM ||
        reg_index(arm->operands[1].mem.base) != base_reg ||
        arm->operands[1].mem.index != ARM_REG_INVALID ||
        arm->operands[1].mem.disp != disp)
        return 0;

    *dst = reg_index(arm->operands[0].reg);
    return *dst >= 0;
}

static int has_indirect_call_after(const arm_analysis_t *a, size_t load_idx,
                                   size_t end, int reg)
{
    size_t limit = load_idx + 8;

    if (limit > end)
        limit = end;

    for (size_t i = load_idx + 1; i < limit; i++) {
        const cs_arm *arm;

        if (a->insn[i].id == ARM_INS_BLX && a->insn[i].detail) {
            arm = &a->insn[i].detail->arm;
            if (arm->op_count >= 1 && arm->operands[0].type == ARM_OP_REG &&
                reg_index(arm->operands[0].reg) == reg)
                return 1;
        }

        if (instruction_writes_reg(&a->insn[i], reg))
            break;
    }

    return 0;
}

static int instruction_has_imm(const cs_insn *insn, uint32_t value)
{
    const cs_arm *arm;

    if (!insn || !insn->detail)
        return 0;

    arm = &insn->detail->arm;
    for (unsigned i = 0; i < arm->op_count; i++) {
        if (arm->operands[i].type == ARM_OP_IMM &&
            (uint32_t)arm->operands[i].imm == value)
            return 1;
    }

    return 0;
}

static int generic_read_signature_score(const arm_analysis_t *a,
                                        size_t begin, size_t end)
{
    int dev_reg = -1;
    int read_reg = -1;
    int write_reg = -1;
    int have_blkdev = 0;
    int have_read = 0;
    int have_write = 0;
    int have_block_size = 0;
    int have_shift9 = 0;

    for (size_t i = begin; i < end; i++) {
        if (load_reg_from_mem(&a->insn[i], 0, 0x8, &dev_reg))
            continue;

        if (load_reg_from_mem(&a->insn[i], 0, 0x4, &read_reg))
            have_blkdev = 1;

        if (dev_reg >= 0 && load_reg_from_mem(&a->insn[i], dev_reg, 0xc, &read_reg) &&
            has_indirect_call_after(a, i, end, read_reg))
            have_read = 1;

        if (dev_reg >= 0 && load_reg_from_mem(&a->insn[i], dev_reg, 0x10, &write_reg) &&
            has_indirect_call_after(a, i, end, write_reg))
            have_write = 1;

        if (instruction_has_imm(&a->insn[i], 0x200))
            have_block_size = 1;

        if (strstr(a->insn[i].mnemonic, "lsr") &&
            strstr(a->insn[i].op_str, "#0x9"))
            have_shift9 = 1;
    }

    /*
     * mt_part_generic_read() on MT6589/eMMC has:
     *   dev->blkdev at +0x8
     *   block_read at +0xc
     *   block_read at +0x10
     *   512-byte blocks (0x200 / <<9)
     *   dev->read/dev->blkdev field access at +0x4
     */
    return (dev_reg >= 0 ? 2 : 0) +
           (have_blkdev ? 1 : 0) +
           (have_read ? 3 : 0) +
           (have_write ? 3 : 0) +
           (have_block_size ? 2 : 0) +
           (have_shift9 ? 1 : 0);
}

static int find_mt_part_generic_read_signature(const arm_analysis_t *a,
                                               size_t before_idx, uint32_t *addr)
{
    size_t best_begin = SIZE_MAX;
    size_t best_end = 0;
    int best_score = 0;
    uint32_t anchor_va;

    if (before_idx >= a->count)
        return -1;

    anchor_va = (uint32_t)a->insn[before_idx].address;

    for (size_t begin = 0; begin < before_idx; begin++) {
        uint32_t fn_va;
        size_t end;
        int score;

        if (!is_prologue(&a->insn[begin]))
            continue;

        fn_va = (uint32_t)a->insn[begin].address;
        if (anchor_va < fn_va || anchor_va - fn_va > MAX_FUNCTION_SEARCH)
            continue;

        end = begin + 1;
        while (end < a->count) {
            if (is_prologue(&a->insn[end]))
                break;
            if ((uint32_t)a->insn[end].address - fn_va > MAX_FUNCTION_SEARCH)
                break;
            end++;
        }

        score = generic_read_signature_score(a, begin, end);
        if (score < 10)
            continue;

        if (best_begin == SIZE_MAX || score > best_score ||
            (score == best_score && begin > best_begin)) {
            best_begin = begin;
            best_end = end;
            best_score = score;
        }
    }

    if (best_begin == SIZE_MAX)
        return -1;

    *addr = function_address(a, best_begin);
    fprintf(stderr,
            "[analyzer] mt_part_generic_read: signature candidate function="
            "[0x%08x,0x%08x) score=%d\n",
            (uint32_t)a->insn[best_begin].address,
            best_end < a->count ? (uint32_t)a->insn[best_end].address
                                : (uint32_t)(a->insn[a->count - 1].address +
                                             a->insn[a->count - 1].size),
            best_score);
    return 0;
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
                    a->insn[j].detail->arm.op_count)
                    blxs++;
            }

            if (lits >= 2 && blxs >= 4) {
                *best_begin = block_start;
                *best_end = block_end;
                return 0;
            }

            block_start = i + 1;
        }
    }

    return -1;
}

static int try_preloader_dl_ul_mode(const uint8_t *data, uint32_t size, uint32_t base,
                                    int thumb, uint32_t *ptr_dl, uint32_t *ptr_ul)
{
    const char *pat = "%s sync time %dms\n";
    arm_analysis_t a;
    size_t refs = 0;
    uint32_t search_off = 0;
    uint32_t str_len = (uint32_t)strlen(pat);

    if (!str_len || str_len > size) {
        fprintf(stderr, "[analyzer] ptr_dl/ptr_ul: string not found: %s\n", pat);
        return -1;
    }

    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    /*
     * Do not assume the first occurrence is the referenced string.
     * Real preloaders may contain multiple identical copies of a format
     * string.  Upstream blocks_by_str() effectively searches all matching
     * string anchors.
     */
    while (search_off <= size - str_len) {
        const uint8_t *found =
            find_string_from(data, size, pat, search_off);
        size_t next_search;
        uint32_t str_va;

        if (!found)
            break;

        next_search = (size_t)(found - data);
        search_off = (uint32_t)next_search + 1;
        str_va = base + (uint32_t)next_search;

        fprintf(stderr,
                "[analyzer] ptr_dl/ptr_ul: found string at +0x%x, mode=%s\n",
                (unsigned)next_search, thumb ? "Thumb" : "ARM");

        for (size_t ref_idx = 0; ref_idx < a.count; ref_idx++) {
            size_t begin, end;

            if (!instruction_refers_to(&a, &a.insn[ref_idx], str_va))
                continue;

            refs++;
            if (find_function_range(&a, ref_idx, &begin, &end) != 0)
                continue;

            fprintf(stderr,
                    "[analyzer] ptr_dl/ptr_ul: xref=0x%08x function=[0x%08x,0x%08x) (%s)\n",
                    (uint32_t)a.insn[ref_idx].address,
                    (uint32_t)a.insn[begin].address,
                    end < a.count ? (uint32_t)a.insn[end].address
                                  : (uint32_t)(a.insn[a.count - 1].address +
                                               a.insn[a.count - 1].size),
                    thumb ? "Thumb" : "ARM");

            for (size_t i = begin; i < end; i++) {
                const cs_arm *arm;
                int r;
                reg_value_t array;
        /* The Preloader callback table is laid out as [UL, DL]. */
        uint32_t ul, dl;

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

        if (read_u32_va(&a, array.value, &ul) != 0 ||
            read_u32_va(&a, array.value + 4, &dl) != 0)
            continue;

                if (!ptr_in_image(&a, dl, 1) || !ptr_in_image(&a, ul, 1))
                    continue;

                if (!(dl & 1) || !(ul & 1))
                    continue;

                *ptr_dl = dl;
                *ptr_ul = ul;
                fprintf(stderr,
                        "[analyzer] ptr_dl/ptr_ul: success dl=0x%08x ul=0x%08x (%s)\n",
                        dl, ul, thumb ? "Thumb" : "ARM");
                close_analysis(&a);
                return 0;
            }
        }
    }

    fprintf(stderr,
            "[analyzer] ptr_dl/ptr_ul: no valid LDM-backed DL/UL pair"
            " after %zu string references (%s mode)\n",
            refs, thumb ? "Thumb" : "ARM");
    close_analysis(&a);
    return -1;
}

int extract_preloader_dl_ul(const uint8_t *data, uint32_t size, uint32_t base,
                            uint32_t *ptr_dl, uint32_t *ptr_ul)
{
    if (try_preloader_dl_ul_mode(data, size, base, 1, ptr_dl, ptr_ul) == 0)
        return 0;
    fprintf(stderr, "[analyzer] ptr_dl/ptr_ul: Thumb analysis failed, retrying ARM\n");
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
    size_t ref_idx = 0;
    size_t begin = 0, end = 0;
    size_t block_begin = 0, block_end = 0;
    size_t function_begin = 0, function_end = 0;
    int have_block = 0;

    if (!found) {
        fprintf(stderr, "[analyzer] bldr_jump: string not found: %s\n", pat);
    } else {
        fprintf(stderr, "[analyzer] bldr_jump: found string at +0x%x, mode=%s\n",
                (unsigned)(found - data), thumb ? "Thumb" : "ARM");
    }

    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    if (found) {
        uint32_t str_va = base + (uint32_t)(found - data);

        if (find_string_function(&a, str_va, &begin, &end, &ref_idx) == 0) {
            fprintf(stderr,
                    "[analyzer] bldr_jump: reference=0x%08x function=[0x%08x,0x%08x) (%s)\n",
                    (uint32_t)a.insn[ref_idx].address,
                    (uint32_t)a.insn[begin].address,
                    end < a.count ? (uint32_t)a.insn[end].address
                                  : (uint32_t)(a.insn[a.count - 1].address +
                                               a.insn[a.count - 1].size),
                    thumb ? "Thumb" : "ARM");

            if (block_has_pattern(&a, begin, end, &block_begin, &block_end) == 0) {
                function_begin = begin;
                function_end = end;
                have_block = 1;
            } else {
                fprintf(stderr,
                        "[analyzer] bldr_jump: no suitable basic block found (%s mode)\n",
                        thumb ? "Thumb" : "ARM");
            }
        } else {
            fprintf(stderr,
                    "[analyzer] bldr_jump: no code reference to string VA 0x%08x (%s mode)\n",
                    str_va, thumb ? "Thumb" : "ARM");
        }
    }

    /*
     * Some preloaders have no statically recoverable xref from the
     * usbdl_jump_da() format string.  The upstream extractor does not
     * actually need the string reference to identify the block: the
     * characteristic pattern itself is sufficiently strong.
     */
    if (!have_block) {
        fprintf(stderr,
                "[analyzer] bldr_jump: scanning all basic blocks for"
                " upstream pattern (%s mode)\n",
                thumb ? "Thumb" : "ARM");

        if (block_has_pattern(&a, 0, a.count, &block_begin, &block_end) != 0) {
            fprintf(stderr,
                    "[analyzer] bldr_jump: no matching basic block found (%s mode)\n",
                    thumb ? "Thumb" : "ARM");
            close_analysis(&a);
            return -1;
        }

        if (find_function_range(&a, block_begin, &function_begin, &function_end) != 0) {
            function_begin = block_begin;
            function_end = block_end;
        }

        fprintf(stderr,
                "[analyzer] bldr_jump: fallback block=[0x%08x,0x%08x)"
                " function=[0x%08x,0x%08x) (%s)\n",
                (uint32_t)a.insn[block_begin].address,
                block_end < a.count ? (uint32_t)a.insn[block_end].address
                                    : (uint32_t)(a.insn[a.count - 1].address +
                                                 a.insn[a.count - 1].size),
                (uint32_t)a.insn[function_begin].address,
                function_end < a.count ? (uint32_t)a.insn[function_end].address
                                       : (uint32_t)(a.insn[a.count - 1].address +
                                                    a.insn[a.count - 1].size),
                thumb ? "Thumb" : "ARM");
    }

    uint32_t last_target = 0;
    for (size_t i = block_begin; i < block_end; i++) {
        uint32_t target;
        if ((a.insn[i].id == ARM_INS_BL || a.insn[i].id == ARM_INS_BLX) &&
            call_target(&a, function_begin, i, &target) == 0)
                last_target = target;
    }

    if (!last_target || !ptr_in_image(&a, last_target, 1)) {
        fprintf(stderr,
                "[analyzer] bldr_jump: no valid BL/BLX target in candidate block"
                " (target=0x%08x)\n",
                last_target);
        close_analysis(&a);
        return -1;
    }

    fprintf(stderr, "[analyzer] bldr_jump: candidate jump target=0x%08x\n",
            last_target);

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
        fprintf(stderr,
                "[analyzer] bldr_jump: no 4KiB-aligned DA address literal found\n");
        close_analysis(&a);
        return -1;
    }

    *bldr_jump = last_target | 1u;
    *da_addr = da;
    close_analysis(&a);
    return 0;
}

int extract_bldr_jump(const uint8_t *data, uint32_t size, uint32_t base,
                      uint32_t *bldr_jump, uint32_t *da_addr)
{
    if (try_bldr_jump_mode(data, size, base, 1, bldr_jump, da_addr) == 0)
        return 0;
    fprintf(stderr, "[analyzer] bldr_jump: Thumb analysis failed, retrying ARM\n");
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

static int string_at_va_is(const arm_analysis_t *a, uint32_t va,
                           const char *value)
{
    uint32_t off;
    size_t len;

    if (!a || !value || va < a->base)
        return 0;

    off = va - a->base;
    len = strlen(value);
    if (off > a->size || len > a->size - off)
        return 0;

    return memcmp(a->data + off, value, len) == 0;
}

static int try_most_called_target_by_string_mode(const uint8_t *data,
                                                 uint32_t size,
                                                 uint32_t base, int thumb,
                                                 const char *pat,
                                                 uint32_t *addr)
{
    const uint8_t *found = find_string(data, size, pat);
    arm_analysis_t a;
    size_t begin, end, ref_idx;
    uint32_t targets[32];
    unsigned counts[32];
    size_t target_count = 0;
    unsigned best_count = 0;
    uint32_t best_target = 0;

    if (!found || open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    {
        uint32_t str_va = base + (uint32_t)(found - data);

        if (find_string_function(&a, str_va, &begin, &end, &ref_idx) != 0) {
            close_analysis(&a);
            return -1;
        }
    }

    for (size_t i = begin; i < end; i++) {
        uint32_t target;
        size_t j;

        if (call_target(&a, begin, i, &target) != 0 ||
            !ptr_in_image(&a, target, 1))
            continue;

        for (j = 0; j < target_count; j++) {
            if (targets[j] == target)
                break;
        }

        if (j == target_count) {
            if (target_count == sizeof(targets) / sizeof(targets[0]))
                continue;
            targets[target_count] = target;
            counts[target_count] = 1;
            j = target_count++;
        } else {
            counts[j]++;
        }

        if (counts[j] > best_count ||
            (counts[j] == best_count && target < best_target)) {
            best_count = counts[j];
            best_target = target;
        }
    }

    (void)ref_idx;
    close_analysis(&a);

    /* fastboot_init() calls fastboot_register() much more often than any
     * other helper (9 calls in the Blade 10 KitKat image). */
    if (best_count < 3)
        return -1;

    *addr = best_target;
    fprintf(stderr,
            "[analyzer] %s: most-called target=0x%08x count=%u\n",
            pat, best_target, best_count);
    return 0;
}

int extract_fastboot_init(const uint8_t *data, uint32_t size, uint32_t base,
                          uint32_t *addr)
{
    if (try_function_by_string_mode(data, size, base, 1,
                                    "fastboot_init()\n", addr) == 0)
        return 0;
    return try_function_by_string_mode(data, size, base, 0,
                                       "fastboot_init()\n", addr);
}

int extract_mtk_wdt_init(const uint8_t *data, uint32_t size, uint32_t base,
                         uint32_t *addr)
{
    if (try_function_by_string_mode(data, size, base, 1,
                                    "UB wdt init\n", addr) == 0)
        return 0;
    return try_function_by_string_mode(data, size, base, 0,
                                       "UB wdt init\n", addr);
}

int extract_fastboot_register(const uint8_t *data, uint32_t size,
                              uint32_t base, uint32_t *addr)
{
    if (try_most_called_target_by_string_mode(data, size, base, 1,
                                              "fastboot_init()\n", addr) == 0)
        return 0;
    return try_most_called_target_by_string_mode(data, size, base, 0,
                                                 "fastboot_init()\n", addr);
}

static int try_fastboot_fail_mode(const uint8_t *data, uint32_t size,
                                  uint32_t base, int thumb, uint32_t *addr)
{
    const char *pat = "unknown command";
    const uint8_t *found = find_string(data, size, pat);
    arm_analysis_t a;
    uint32_t str_va;
    size_t ref;
    size_t limit;

    if (!found || open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    str_va = base + (uint32_t)(found - data);
    if (find_reference(&a, str_va, &ref) != 0) {
        close_analysis(&a);
        return -1;
    }

    limit = ref + 8;
    if (limit > a.count)
        limit = a.count;

    /* cmd_loop() emits "unknown command" and immediately calls
     * fastboot_fail().  Anchor on the string xref instead of a fixed offset. */
    for (size_t i = ref; i < limit; i++) {
        uint32_t target;

        if (call_target(&a, 0, i, &target) != 0)
            continue;

        *addr = target;
        fprintf(stderr,
                "[analyzer] fastboot_fail: string=xref 0x%08x target=0x%08x\n",
                (uint32_t)a.insn[ref].address, target);
        close_analysis(&a);
        return 0;
    }

    close_analysis(&a);
    return -1;
}

int extract_fastboot_fail(const uint8_t *data, uint32_t size, uint32_t base,
                          uint32_t *addr)
{
    if (try_fastboot_fail_mode(data, size, base, 1, addr) == 0)
        return 0;
    return try_fastboot_fail_mode(data, size, base, 0, addr);
}

static int find_instruction_index(const arm_analysis_t *a, uint32_t address,
                                  size_t *idx)
{
    if (!a || !idx)
        return -1;

    for (size_t i = 0; i < a->count; i++) {
        if ((uint32_t)a->insn[i].address == address) {
            *idx = i;
            return 0;
        }
    }

    return -1;
}

static int ack_wrapper_matches(const arm_analysis_t *a, size_t idx,
                               const char *code, uint32_t *ack_target)
{
    const cs_insn *mov;
    const cs_insn *ldr;
    const cs_insn *add;
    const cs_insn *branch;
    uint32_t target;
    reg_value_t resolved;

    if (!a || !code || idx + 3 >= a->count)
        return -1;

    mov = &a->insn[idx];
    ldr = &a->insn[idx + 1];
    add = &a->insn[idx + 2];
    branch = &a->insn[idx + 3];

    if (mov->id != ARM_INS_MOV || !mov->detail ||
        mov->detail->arm.op_count < 2 ||
        mov->detail->arm.operands[0].type != ARM_OP_REG ||
        mov->detail->arm.operands[1].type != ARM_OP_REG ||
        mov->detail->arm.operands[0].reg != ARM_REG_R1 ||
        mov->detail->arm.operands[1].reg != ARM_REG_R0)
        return -1;

    if (ldr->id != ARM_INS_LDR || !ldr->detail ||
        ldr->detail->arm.op_count < 2 ||
        ldr->detail->arm.operands[0].type != ARM_OP_REG ||
        ldr->detail->arm.operands[1].type != ARM_OP_MEM ||
        ldr->detail->arm.operands[0].reg != ARM_REG_R0 ||
        ldr->detail->arm.operands[1].mem.base != ARM_REG_PC)
        return -1;

    if (add->id != ARM_INS_ADD || !add->detail ||
        add->detail->arm.op_count < 2 ||
        add->detail->arm.operands[0].type != ARM_OP_REG ||
        add->detail->arm.operands[1].type != ARM_OP_REG ||
        add->detail->arm.operands[0].reg != ARM_REG_R0 ||
        add->detail->arm.operands[1].reg != ARM_REG_PC)
        return -1;

    if (branch_target(branch, &target) != 0)
        return -1;

    resolved = resolve_reg_before(a, idx, idx + 3, 0, 0);
    if (!value_is_full(resolved) || !string_at_va_is(a, resolved.value, code))
        return -1;

    *ack_target = target;
    return 0;
}

static int try_fastboot_okay_mode(const uint8_t *data, uint32_t size,
                                  uint32_t base, int thumb,
                                  uint32_t fastboot_fail, uint32_t *addr)
{
    arm_analysis_t a;
    size_t fail_idx;
    uint32_t ack_target;

    if (open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    if (find_instruction_index(&a, fastboot_fail, &fail_idx) != 0 ||
        ack_wrapper_matches(&a, fail_idx, "FAIL\n", &ack_target) != 0) {
        close_analysis(&a);
        return -1;
    }

    /* fastboot_okay() is the sibling four-instruction wrapper which tail
     * branches to the same fastboot_ack() implementation, but supplies the
     * literal "OKAY\n" instead of "FAIL\n". */
    for (size_t i = 0; i + 3 < a.count; i++) {
        uint32_t candidate_ack_target;

        if ((uint32_t)a.insn[i].address == fastboot_fail)
            continue;
        if (ack_wrapper_matches(&a, i, "OKAY\n", &candidate_ack_target) != 0)
            continue;
        if (candidate_ack_target != ack_target)
            continue;

        *addr = (uint32_t)a.insn[i].address;
        fprintf(stderr,
                "[analyzer] fastboot_okay: sibling wrapper=0x%08x ack=0x%08x\n",
                *addr, ack_target);
        close_analysis(&a);
        return 0;
    }

    close_analysis(&a);
    return -1;
}

int extract_fastboot_okay(const uint8_t *data, uint32_t size, uint32_t base,
                          uint32_t *addr)
{
    uint32_t fastboot_fail;

    if (extract_fastboot_fail(data, size, base, &fastboot_fail) != 0)
        return -1;

    if (try_fastboot_okay_mode(data, size, base, 1,
                               fastboot_fail, addr) == 0)
        return 0;
    return try_fastboot_okay_mode(data, size, base, 0,
                                  fastboot_fail, addr);
}

static int try_udc_stop_mode(const uint8_t *data, uint32_t size,
                             uint32_t base, int thumb,
                             uint32_t mtk_wdt_init, uint32_t *addr)
{
    const char *pat = "phone will continue boot up after 5s...";
    const uint8_t *found = find_string(data, size, pat);
    arm_analysis_t a;
    uint32_t str_va;
    size_t ref;
    size_t start;

    if (!found || open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    str_va = base + (uint32_t)(found - data);
    if (find_reference(&a, str_va, &ref) != 0) {
        close_analysis(&a);
        return -1;
    }

    start = ref > 32 ? ref - 32 : 0;
    for (size_t i = start; i + 1 < ref; i++) {
        uint32_t first;
        uint32_t second;

        if (call_target(&a, 0, i, &first) != 0 ||
            call_target(&a, 0, i + 1, &second) != 0)
            continue;

        /* cmd_continue() calls udc_stop() immediately before mtk_wdt_init(). */
        if (second != mtk_wdt_init)
            continue;

        *addr = first;
        fprintf(stderr,
                "[analyzer] udc_stop: preceding mtk_wdt_init target=0x%08x\n",
                first);
        close_analysis(&a);
        return 0;
    }

    close_analysis(&a);
    return -1;
}

int extract_udc_stop(const uint8_t *data, uint32_t size, uint32_t base,
                     uint32_t *addr)
{
    uint32_t mtk_wdt_init;

    if (extract_mtk_wdt_init(data, size, base, &mtk_wdt_init) != 0)
        return -1;
    if (try_udc_stop_mode(data, size, base, 1, mtk_wdt_init, addr) == 0)
        return 0;
    return try_udc_stop_mode(data, size, base, 0, mtk_wdt_init, addr);
}

int extract_mt_boot_init(const uint8_t *data, uint32_t size, uint32_t base,
                         uint32_t *addr)
{
    if (try_function_by_string_mode(data, size, base, 1,
                                    "app/mt_boot/mt_boot.c", addr) == 0)
        return 0;
    return try_function_by_string_mode(data, size, base, 0,
                                       "app/mt_boot/mt_boot.c", addr);
}

static int try_boot_mode_addr_mode(const uint8_t *data, uint32_t size,
                                   uint32_t base, int thumb, uint32_t *addr)
{
    const uint8_t *found = find_string(data, size, "app/mt_boot/mt_boot.c");
    arm_analysis_t a;
    uint32_t str_va;
    size_t begin, end, ref_idx;

    if (!found || open_analysis(&a, data, size, base, thumb) != 0)
        return -1;

    str_va = base + (uint32_t)(found - data);
    if (find_string_function(&a, str_va, &begin, &end, &ref_idx) != 0) {
        close_analysis(&a);
        return -1;
    }

    for (size_t i = begin + 1; i < end; i++) {
        const cs_insn *cmp = &a.insn[i];
        const cs_insn *load;
        const cs_arm *cmp_arm;
        const cs_arm *load_arm;
        int reg;
        int load_base;
        reg_value_t value;

        if (!cmp->detail || cmp->id != ARM_INS_CMP ||
            cmp->detail->arm.op_count < 2 ||
            cmp->detail->arm.operands[0].type != ARM_OP_REG ||
            cmp->detail->arm.operands[1].type != ARM_OP_IMM ||
            (uint32_t)cmp->detail->arm.operands[1].imm != 99u)
            continue;

        cmp_arm = &cmp->detail->arm;
        reg = reg_index(cmp_arm->operands[0].reg);
        if (reg < 0 || i == begin)
            continue;

        load = &a.insn[i - 1];
        if (!load->detail || load->id != ARM_INS_LDR ||
            load->detail->arm.op_count < 2 ||
            load->detail->arm.operands[0].type != ARM_OP_REG ||
            reg_index(load->detail->arm.operands[0].reg) != reg ||
            load->detail->arm.operands[1].type != ARM_OP_MEM)
            continue;

        load_arm = &load->detail->arm;
        load_base = reg_index(load_arm->operands[1].mem.base);
        if (load_base != reg || load_arm->operands[1].mem.disp != 0)
            continue;

        /* Resolve the LDR which feeds the final g_boot_mode load.  Its
         * effective address is the GOT slot and its loaded value is the
         * runtime address of g_boot_mode; we intentionally do not read the
         * BSS object itself because it is absent from the file image. */
        if (i < begin + 2 ||
            a.insn[i - 2].id != ARM_INS_LDR ||
            !a.insn[i - 2].detail ||
            a.insn[i - 2].detail->arm.op_count < 2 ||
            a.insn[i - 2].detail->arm.operands[0].type != ARM_OP_REG ||
            reg_index(a.insn[i - 2].detail->arm.operands[0].reg) != reg ||
            a.insn[i - 2].detail->arm.operands[1].type != ARM_OP_MEM ||
            a.insn[i - 2].detail->arm.operands[1].mem.index == ARM_REG_INVALID)
            continue;

        value = resolve_definition(&a, begin, i - 2, reg, 0);
        if (!value_is_full(value) || value.value < 0x80000000u)
            continue;

        *addr = value.value;
        fprintf(stderr,
                "[analyzer] boot_mode_addr: cmp #99 uses global=0x%08x\n",
                *addr);
        close_analysis(&a);
        return 0;
    }

    close_analysis(&a);
    return -1;
}

int extract_boot_mode_addr(const uint8_t *data, uint32_t size, uint32_t base,
                           uint32_t *addr)
{
    if (try_boot_mode_addr_mode(data, size, base, 1, addr) == 0)
        return 0;
    return try_boot_mode_addr_mode(data, size, base, 0, addr);
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

int extract_boot_linux_from_storage(const uint8_t *data, uint32_t size,
                                    uint32_t base, uint32_t *addr)
{
    /*
     * boot_linux_from_storage() is the only MT6589 LK function which passes
     * the literal "Android Boot Image" to the image-load error helpers.
     * Resolve the containing function from the actual LK image instead of
     * depending on a fixed offset.
     */
    if (try_function_by_string_mode(data, size, base, 1,
                                    "Android Boot Image", addr) == 0)
        return 0;
    return try_function_by_string_mode(data, size, base, 0,
                                       "Android Boot Image", addr);
}

int extract_get_part(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *addr)
{
    if (try_function_by_string_mode(data, size, base, 1, "get_part", addr) == 0)
        return 0;
    return try_function_by_string_mode(data, size, base, 0, "get_part", addr);
}

/*
 * mt_part_register_device() normally gets the default read callback through
 * an indirect table load such as:
 *
 *     ldr   r2, [literal]
 *     add   r3, pc
 *     ldr   r3, [r3, r2]
 *     str   r3, [r4, #0x10]
 *
 * The generic register resolver can mistake the incoming value of r3 for
 * the callback itself because the callback is loaded from a table rather
 * than from MOVW/MOVT immediates. Resolve that short, local pattern
 * explicitly and read the callback value from the image.
 */
static int resolve_indexed_ldr_value(const arm_analysis_t *a, size_t begin,
                                     size_t at, int dst_reg, uint32_t *value)
{
    size_t first;

    if (at <= begin)
        return -1;

    first = at > 12 ? at - 12 : begin;
    if (first < begin)
        first = begin;

    for (size_t i = at; i > first; i--) {
        size_t idx = i - 1;
        const cs_insn *insn = &a->insn[idx];
        const cs_arm *arm;
        int base_reg;
        reg_value_t base;
        uint32_t address;

        if (insn->id != ARM_INS_LDR || !insn->detail)
            continue;

        arm = &insn->detail->arm;
        if (arm->op_count < 2 ||
            arm->operands[0].type != ARM_OP_REG ||
            reg_index(arm->operands[0].reg) != dst_reg ||
            arm->operands[1].type != ARM_OP_MEM)
            continue;

        base_reg = reg_index(arm->operands[1].mem.base);
        if (base_reg < 0)
            continue;

        base = resolve_reg_before(a, begin, idx, base_reg, 0);
        if (!value_is_full(base))
            continue;

        address = base.value + (int32_t)arm->operands[1].mem.disp;

        if (arm->operands[1].mem.index != ARM_REG_INVALID) {
            int index_reg =
                reg_index(arm->operands[1].mem.index);
            reg_value_t index;

            if (index_reg < 0)
                continue;

            index = resolve_reg_before(a, begin, idx, index_reg, 0);
            if (!value_is_full(index))
                continue;

            address += index.value;
        }

        if (read_u32_va(a, address, value) == 0)
            return 0;
    }

    return -1;
}

/*
 * Resolve the callback stored in dev + 0x10 by following the predecessor
 * edge into the block which performs the indexed function-table load.
 *
 * On the Lenovo MT6589 KitKat LK this is:
 *
 *     0x81e053f2: cbz  r2, 0x81e05432
 *     0x81e05432: ldr  r2, [literal]  ; r2 = 0x14c
 *     0x81e05434: ldr  r3, [r3, r2]
 *     0x81e05436: str  r3, [r4, #0x10]
 *
 * The table base in r3 is established before the predecessor branch.
 * Resolving it from that predecessor avoids crossing later BL calls that
 * clobber r3 and avoids selecting an unrelated data pointer such as dev+8.
 */
static int resolve_mt_part_read_callback(const arm_analysis_t *a,
                                         size_t function_begin,
                                         size_t block_begin,
                                         size_t str_idx,
                                         uint32_t *value)
{
    const cs_insn *str_insn = &a->insn[str_idx];
    const cs_arm *str_arm;
    int read_reg;
    int base_reg = -1;
    int index_reg = -1;
    size_t load_idx = SIZE_MAX;
    size_t predecessor = SIZE_MAX;
    uint32_t index_value = 0;
    uint32_t block_va;
    int32_t table_disp = 0;
    int have_index = 0;

    if (!str_insn->detail || str_insn->id != ARM_INS_STR)
        return -1;

    str_arm = &str_insn->detail->arm;
    if (str_arm->op_count < 2 ||
        str_arm->operands[0].type != ARM_OP_REG ||
        str_arm->operands[1].type != ARM_OP_MEM ||
        str_arm->operands[1].mem.disp != 0x10)
        return -1;

    read_reg = reg_index(str_arm->operands[0].reg);
    if (read_reg < 0)
        return -1;

    /* Find the indexed LDR which defines the STR source register. */
    for (size_t i = block_begin; i < str_idx; i++) {
        const cs_insn *insn = &a->insn[i];
        const cs_arm *arm;
        int dst;
        int base;
        int index;

        if (insn->id != ARM_INS_LDR || !insn->detail)
            continue;

        arm = &insn->detail->arm;
        if (arm->op_count < 2 ||
            arm->operands[0].type != ARM_OP_REG ||
            arm->operands[1].type != ARM_OP_MEM ||
            arm->operands[1].mem.index == ARM_REG_INVALID)
            continue;

        dst = reg_index(arm->operands[0].reg);
        if (dst != read_reg)
            continue;

        base = reg_index(arm->operands[1].mem.base);
        index = reg_index(arm->operands[1].mem.index);
        if (base < 0 || index < 0)
            continue;

        table_disp = arm->operands[1].mem.disp;
        load_idx = i;
        base_reg = base;
        index_reg = index;
    }

    if (load_idx == SIZE_MAX)
        return -1;

    /* The table index is normally a PC-relative literal load. */
    for (size_t i = block_begin; i < load_idx; i++) {
        const cs_insn *insn = &a->insn[i];
        const cs_arm *arm;
        int dst;

        if (insn->id != ARM_INS_LDR || !insn->detail)
            continue;

        arm = &insn->detail->arm;
        if (arm->op_count < 2 ||
            arm->operands[0].type != ARM_OP_REG)
            continue;

        dst = reg_index(arm->operands[0].reg);
        if (dst != index_reg)
            continue;

        if (literal_value(a, insn, &index_value) == 0)
            have_index = 1;
    }

    if (!have_index)
        return -1;

    /* Find the branch which enters this block and carry state from there. */
    block_va = (uint32_t)a->insn[block_begin].address;
    for (size_t i = function_begin; i < block_begin; i++) {
        uint32_t target;

        if (branch_target(&a->insn[i], &target) == 0 && target == block_va)
            predecessor = i;
    }

    if (predecessor == SIZE_MAX)
        return -1;

    reg_value_t base_value =
        resolve_reg_before(a, function_begin, predecessor, base_reg, 0);
    if (!value_is_full(base_value))
        return -1;

    int64_t table_address = (int64_t)(uint32_t)base_value.value +
                            (int64_t)index_value + table_disp;
    if (table_address < 0 || table_address > UINT32_MAX)
        return -1;

    if (read_u32_va(a, (uint32_t)table_address, value) != 0)
        return -1;

    if (*value == 0 || !(*value & 1) || !ptr_in_image(a, *value, 1))
        return -1;

    return 0;
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
        int found_read_store = 0;
        if (find_reference(&a, str_va, &ref) != 0)
            continue;

        size_t begin, end;
        if (find_function_range(&a, ref, &begin, &end) != 0)
            continue;

        /*
         * mt_part_register_device() has an early POP {..,pc}, but the
         * callback-assignment blocks are still part of the same function.
         */
        while (end < a.count && !is_prologue(&a.insn[end]))
            end++;

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
                        found_read_store = 1;

                        /*
                         * For MT6589 the actual dev->read callback is loaded
                         * from a function-pointer table in this branch.
                         * Resolve that value before falling back to the
                         * generic-read signature heuristic; the latter can
                         * otherwise select a different helper function.
                         */
                        {
                            uint32_t callback;

                            if (resolve_mt_part_read_callback(
                                    &a, begin, block_begin, j, &callback) == 0) {
                                fprintf(stderr,
                                        "[analyzer] mt_part_generic_read:"
                                        " resolved dev->read callback=0x%08x\n",
                                        callback);
                                *addr = callback;
                                close_analysis(&a);
                                return 0;
                            }
                        }

                        src = reg_index(arm->operands[0].reg);
                        if (src < 0)
                            continue;
                        /*
                         * The STR source may be defined in a predecessor
                         * basic block.  The upstream extractor resolves the
                         * block's incoming register state, so do not limit
                         * the backwards walk to block_begin here.
                         */
                        value = resolve_reg_before(&a, begin, j, src, 0);

                        /*
                         * The default read callback in some MT6589 LK builds
                         * is loaded from an indexed function-pointer table.
                         * Prefer that exact value over a bogus data-flow
                         * result such as the table's address itself.
                         */
                        {
                            int valid = value_is_full(value) &&
                                        value.value != 0 &&
                                        (value.value & 1) &&
                                        ptr_in_image(&a, value.value, 1);

                            if (!valid) {
                                uint32_t callback;

                                if (resolve_indexed_ldr_value(
                                        &a, begin, j, src, &callback) == 0) {
                                    value = reg_full(callback);
                                    fprintf(stderr,
                                            "[analyzer] mt_part_generic_read:"
                                            " resolved dev->read callback=0x%08x\n",
                                            callback);
                                }
                            }
                        }

                        if (!value_is_full(value))
                            continue;
                        /*
                         * mt_part_generic_read is not required to live
                         * inside the LK image.  The upstream extractor does
                         * not impose an LK-image range check either, but the
                         * local data-flow resolver is only a heuristic and
                         * can pick a definition from another basic block.
                         * Do not accept an arbitrary constant as a callback
                         * address: the hook path requires Thumb LK code here.
                         */
                        if (value.value == 0 ||
                            !(value.value & 1) ||
                            !ptr_in_image(&a, value.value, 1)) {
                            fprintf(stderr,
                                    "[analyzer] mt_part_generic_read:"
                                    " reject dataflow candidate 0x%08x\n",
                                    value.value);
                            continue;
                        }

                        *addr = value.value;
                        close_analysis(&a);
                        return 0;
                    }
                }

                block_begin = i + 1;
            }
        }

        /*
         * On LK images with runtime-relocated GOT/BSS, the callback pointer at
         * STR [dev, #0x10] is not present in the raw file.  Recover the actual
         * implementation from its code shape instead.
         */
        if (found_read_store && find_mt_part_generic_read_signature(&a, ref, addr) == 0) {
            close_analysis(&a);
            return 0;
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

    fprintf(stderr,
            "[analyze_preloader] input size=0x%x base_hint=0x%08x\n",
            size, base_hint);

    if (image_parse_preloader(data, size, &load_addr, &jump_offset,
                              &content_offset, &content_size) != 0) {
        fprintf(stderr, "[analyze_preloader] FAILED: image_parse_preloader()\n");
        return -1;
    }

    if (content_offset > size) {
        fprintf(stderr,
                "[analyze_preloader] FAILED: content_offset=0x%x > size=0x%x\n",
                content_offset, size);
        return -1;
    }
    if (content_size > size - content_offset) {
        fprintf(stderr,
                "[analyze_preloader] FAILED: content range out of bounds:"
                " offset=0x%x size=0x%x file=0x%x\n",
                content_offset, content_size, size);
        content_size = size - content_offset;
    }

    content = data + content_offset;
    if (load_addr)
        base = load_addr + jump_offset;

    fprintf(stderr,
            "[analyze_preloader] image: load=0x%08x jump=0x%08x"
            " content=[0x%x,0x%x) base=0x%08x\n",
            load_addr, jump_offset, content_offset,
            content_offset + content_size, base);

    if (extract_preloader_dl_ul(content, content_size, base, ptr_dl, ptr_ul) != 0) {
        fprintf(stderr,
                "[analyze_preloader] FAILED: extract_preloader_dl_ul()\n");
        return -1;
    }

    fprintf(stderr,
            "[analyze_preloader] ptr_dl=0x%08x ptr_ul=0x%08x\n",
            *ptr_dl, *ptr_ul);

    if (extract_bldr_jump(content, content_size, base, bldr_jump, da_addr) != 0) {
        fprintf(stderr,
                "[analyze_preloader] FAILED: extract_bldr_jump()\n");
        return -1;
    }

    /* LK base is useful for LK mode but isn't required by Preloader RPC. */
    if (extract_lk_base(content, content_size, base, lk_base) != 0)
        *lk_base = 0;

    return 0;
}
