#include "interceptor.h"
#include "cache.h"
#include "libc_min.h"
#include <stdint.h>

// トランポリンプール
#define MAX_TRAMPOLINES 16
#define MAX_PATCH_SIZE  16
static struct {
    uint32_t target;        // フック対象アドレス
    uint32_t trampoline;    // トランポリンアドレス
    uint32_t jump_back;     // 復帰先
    uint32_t patch_size;    // overwritten bytes
    uint8_t original[MAX_PATCH_SIZE];
} g_trampolines[MAX_TRAMPOLINES];
static int g_trampoline_count = 0;

// バンプアロケータからトランポリン用メモリ取得
extern void *bump_alloc(uint32_t size);

// Thumb-2命令判定
static int is_32bit_instr(uint16_t hw) {
    return (hw >> 11) >= 0x1D && (hw >> 11) <= 0x1F;
}

// LDR literal (16bit) 判定
static int is_ldr_literal(uint16_t hw) {
    return (hw & 0xF800) == 0x4800;
}

// LDR.W literal 判定
static int is_ldr_w_literal(uint16_t hw1, uint16_t hw2) {
    return (hw1 & 0xFF7F) == 0xF85F;
}

// LDR literalの解析
static void parse_ldr_literal(uint16_t instr, uint32_t pc, uint32_t *addr, uint8_t *rt) {
    *rt = (instr >> 8) & 7;
    uint32_t imm = (instr & 0xFF) << 2;
    *addr = (pc + 4) & ~3;
    *addr += imm;
}

// LDR.W literalの解析
static void parse_ldr_w_literal(uint16_t hw1, uint16_t hw2, uint32_t pc,
                                uint32_t *addr, uint8_t *rt, int *add) {
    *add = (hw1 & 0x80) != 0;
    *rt = (hw2 >> 12) & 0xF;
    uint32_t imm = hw2 & 0xFFF;
    uint32_t base = (pc + 4) & ~3;
    *addr = *add ? base + imm : base - imm;
}

// MOVW/MOVT生成
static uint32_t make_movw(uint8_t rd, uint16_t imm) {
    uint32_t i = (imm >> 11) & 1;
    uint32_t imm4 = (imm >> 12) & 0xF;
    uint32_t imm3 = (imm >> 8) & 0x7;
    uint32_t imm8 = imm & 0xFF;
    uint32_t hw1 = 0xF240 | (i << 10) | imm4;
    uint32_t hw2 = (imm3 << 12) | (rd << 8) | imm8;
    return (hw2 << 16) | hw1;
}

static uint32_t make_movt(uint8_t rd, uint16_t imm) {
    uint32_t i = (imm >> 11) & 1;
    uint32_t imm4 = (imm >> 12) & 0xF;
    uint32_t imm3 = (imm >> 8) & 0x7;
    uint32_t imm8 = imm & 0xFF;
    uint32_t hw1 = 0xF2C0 | (i << 10) | imm4;
    uint32_t hw2 = (imm3 << 12) | (rd << 8) | imm8;

    return (hw2 << 16) | hw1;
}

// LDR.W PC, [PC, #0] 生成
static uint32_t make_ldr_pc(void) {
    return 0xF000F8DF;
}

/*
 * Thumb-2 instructions do not have to start on a 4-byte boundary.  In
 * particular, mt_part_generic_read() in the Lenovo MT6589 KitKat LK has a
 * 32-bit STRD at function+0x06.  Do not use uint32_t lvalues for copying
 * instructions, because that makes Clang emit word accesses to unaligned
 * addresses on this path.
 */
static void write_u16(uint8_t *dst, uint16_t value) {
    memcpy(dst, &value, sizeof(value));
}

static void write_u32(uint8_t *dst, uint32_t value) {
    memcpy(dst, &value, sizeof(value));
}

// NOP
static const uint16_t NOP = 0xBF00;

/*
 * This trampoline is intentionally conservative.  Instructions which
 * derive their target from the current PC cannot simply be copied to a
 * different address.  LDR literal is handled separately below.
 */
static int is_pc_relative_16(uint16_t hw) {
    /* B (T1) */
    if ((hw & 0xF800) == 0xE000)
        return 1;

    /* B<cond> (T1), excluding SVC/undefined encodings. */
    if ((hw & 0xF000) == 0xD000 &&
        ((hw >> 8) & 0xF) < 0xE)
        return 1;

    /* CBZ / CBNZ */
    if ((hw & 0xF500) == 0xB100)
        return 1;

    /* ADR (T1) */
    if ((hw & 0xF800) == 0xA000)
        return 1;

    /*
     * High-register ADD/BX-class encoding.  Reject a PC operand or a
     * destination of PC; either can make the copied instruction
     * location-dependent.
     */
    if ((hw & 0xFC00) == 0x4400) {
        uint8_t rd = (uint8_t)((hw & 0x7) | ((hw >> 4) & 0x8));
        uint8_t rm = (uint8_t)((hw >> 3) & 0xF);

        if (rd == 15 || rm == 15)
            return 1;
    }

    return 0;
}

static int is_other_ldr_w_literal(uint16_t hw1, uint16_t hw2) {
    static const uint16_t patterns[] = {
        0xF81F, /* LDRB.W Rt, [PC, #imm] */
        0xF83F, /* LDRH.W Rt, [PC, #imm] */
        0xF91F, /* LDRSB.W Rt, [PC, #imm] */
        0xF93F, /* LDRSH.W Rt, [PC, #imm] */
    };

    (void)hw2;
    for (uint32_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        if ((hw1 & 0xFF7F) == patterns[i])
            return 1;
    }
    return 0;
}

static int is_pc_relative_32(uint16_t hw1, uint16_t hw2) {
    uint16_t op;

    /* LDR.W literal is rewritten to MOVW/MOVT below. */
    if (is_ldr_w_literal(hw1, hw2))
        return 0;

    if (is_other_ldr_w_literal(hw1, hw2))
        return 1;

    /* ADR.W: ADDW/SUBW with PC as the base register. */
    if (hw1 == 0xF20F || hw1 == 0xF2AF)
        return 1;

    /* TBB/TBH use PC as their implicit table base. */
    if (hw1 == 0xE8DF)
        return 1;

    /*
     * Thumb-2 B.W / B<cond>.W / BLX / BL encodings use these second-half
     * word opcode classes when the first halfword is in the Fxxx branch
     * space.
     */
    if ((hw1 & 0xF800) == 0xF000) {
        op = hw2 & 0xF000;
        if (op == 0x8000 || op == 0xB000 ||
            op == 0xE000 || op == 0xF000)
            return 1;
    }

    return 0;
}

// トランポリン生成
static int create_trampoline(uint32_t target, uint32_t *trampoline_out,
                             uint32_t *jump_back_out) {
    uint32_t target_aligned = target & ~1;
    uint32_t thumb = target & 1;
    if (!thumb) return -1; // Thumbモードのみ対応

    // トランポリン用メモリ確保
    uint8_t *code = bump_alloc(64);
    if (!code) return -1;
    uint8_t *orig = (uint8_t*)target_aligned;

    // 命令コピー先
    uint32_t offset = 0;
    uint32_t tramp_offset = 0;
    uint32_t pc_base = target_aligned;

    // アラインメント調整
    if ((uint32_t)code % 4 != 0) {
        write_u16(code + tramp_offset, NOP);
        tramp_offset += 2;
    }

    /*
     * The hook stub occupies 8 bytes for a 4-byte-aligned target, but
     * requires a leading NOP for an unaligned Thumb target.  In that
     * case the overwritten region is 10 bytes, so the trampoline must
     * preserve at least that much original code.
     */
    uint32_t patch_size = (target_aligned % 4 != 0) ? 10 : 8;
    while (offset < patch_size) {
        uint16_t hw1 = *(uint16_t*)(orig + offset);
        if (is_32bit_instr(hw1)) {
            uint16_t hw2 = *(uint16_t*)(orig + offset + 2);
            if (is_pc_relative_32(hw1, hw2))
                return -1;
            if (is_ldr_w_literal(hw1, hw2)) {
                // リテラルをMOVW+MOVTに変換
                uint32_t pc = pc_base + offset;
                uint8_t rt;
                int add;
                uint32_t lit_addr;
                parse_ldr_w_literal(hw1, hw2, pc, &lit_addr, &rt, &add);
                uint32_t value = *(uint32_t*)lit_addr;
                write_u32(code + tramp_offset, make_movw(rt, value & 0xFFFF));
                tramp_offset += 4;
                write_u32(code + tramp_offset, make_movt(rt, value >> 16));
                tramp_offset += 4;
            } else {
                // そのままコピー
                memcpy(code + tramp_offset, orig + offset, 4);
                tramp_offset += 4;
            }
            offset += 4;
        } else {
            if (is_ldr_literal(hw1)) {
                uint32_t pc = pc_base + offset;
                uint8_t rt;
                uint32_t lit_addr;
                parse_ldr_literal(hw1, pc, &lit_addr, &rt);
                uint32_t value = *(uint32_t*)lit_addr;
                write_u32(code + tramp_offset, make_movw(rt, value & 0xFFFF));
                tramp_offset += 4;
                write_u32(code + tramp_offset, make_movt(rt, value >> 16));
                tramp_offset += 4;
            } else if (is_pc_relative_16(hw1)) {
                return -1;
            } else {
                write_u16(code + tramp_offset, hw1);
                tramp_offset += 2;
            }
            offset += 2;
        }
    }

    // アラインメント
    if (tramp_offset % 4 != 0) {
        write_u16(code + tramp_offset, NOP);
        tramp_offset += 2;
    }

    // 復帰ジャンプ追加
    uint32_t jump_back = target_aligned + offset;
    write_u32(code + tramp_offset, make_ldr_pc());
    tramp_offset += 4;
    write_u32(code + tramp_offset, jump_back | 1); // Thumb bit
    tramp_offset += 4;

    // キャッシュフラッシュ
    flush_dcache((uint32_t)code, 64);
    flush_icache();

    *trampoline_out = (uint32_t)code;
    *jump_back_out = jump_back;
	return 0;
}

// フック実行
int interceptor_replace(uint32_t target, void *replacement) {
    uint32_t target_aligned = target & ~1u;
    uint32_t patch_size;
    uint32_t stub_size;
    uint32_t trampoline, jump_back;

    if (!replacement)
        return -1;
    if (g_trampoline_count >= MAX_TRAMPOLINES)
        return -1;

    for (int i = 0; i < g_trampoline_count; i++) {
        if (g_trampolines[i].target == target_aligned)
            return -1;
    }

    if (create_trampoline(target, &trampoline, &jump_back) != 0)
        return -1;
    patch_size = jump_back - target_aligned;
    /*
     * The replacement stub itself is 8 bytes.  An unaligned Thumb entry
     * needs an extra leading NOP, so the actual stub occupies 10 bytes.
     * create_trampoline() may also extend the copied region beyond the
     * 8-byte stub to avoid splitting a 32-bit Thumb-2 instruction.
     */
    stub_size = (target_aligned & 3u) ? 10u : 8u;
    if (patch_size < stub_size || patch_size > MAX_PATCH_SIZE)
        return -1;

    /*
     * Keep a byte-for-byte copy of the overwritten range.  The trampoline
     * itself may contain a leading alignment NOP and rewritten literals, so
     * it is not a valid source for hook restoration.
     */
    memcpy(g_trampolines[g_trampoline_count].original,
           (const void *)(uintptr_t)target_aligned,
           patch_size);

    // 元の関数先頭を書き換え
    uint8_t *target_ptr = (uint8_t*)(uintptr_t)target_aligned;
    // アラインメント調整
    if (target_aligned & 3u) {
        write_u16(target_ptr, NOP);
        target_ptr += 2;
    }
    // LDR.W PC, [PC, #0] + ジャンプ先
    uint32_t jump = make_ldr_pc();
    uint32_t replacement_addr = (uint32_t)(uintptr_t)replacement | 1u;
    write_u32(target_ptr, jump);
    write_u32(target_ptr + 4, replacement_addr);

    /*
     * The trampoline preserves whole instructions, so the target site must
     * cover exactly the same range.  Leave any bytes past the 8-byte jump
     * stub as Thumb NOPs instead of a partial instruction.
     */
    for (uint32_t off = stub_size; off < patch_size; off += 2)
        write_u16((uint8_t *)target_aligned + off, NOP);

    // トランポリン登録
    g_trampolines[g_trampoline_count].target = target_aligned;
    g_trampolines[g_trampoline_count].trampoline = trampoline;
    g_trampolines[g_trampoline_count].jump_back = jump_back;
    g_trampolines[g_trampoline_count].patch_size = patch_size;
    g_trampoline_count++;

    // キャッシュフラッシュ
    flush_dcache(target_aligned, patch_size);
    flush_icache();

    return 0;
}

// オリジナル関数アドレス取得
uint32_t interceptor_original(uint32_t target) {
	for (int i = 0; i < g_trampoline_count; i++) {
		if (g_trampolines[i].target == (target & ~1)) {
			return g_trampolines[i].trampoline | 1u;
		}
	}
	return 0;
}

// フック解除
int interceptor_revert(uint32_t target) {
    for (int i = 0; i < g_trampoline_count; i++) {
        if (g_trampolines[i].target == (target & ~1)) {
            uint8_t *dst = (uint8_t *)(uintptr_t)g_trampolines[i].target;
            uint32_t size = g_trampolines[i].patch_size;

            memcpy(dst, g_trampolines[i].original, size);
            flush_dcache((uint32_t)dst, size);
            flush_icache();

            // 登録削除
            for (int j = i; j < g_trampoline_count - 1; j++) {
                g_trampolines[j] = g_trampolines[j+1];
            }
            g_trampoline_count--;
            return 0;
        }
    }
    return -1;
}
