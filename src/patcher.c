#include "patcher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <capstone/capstone.h>

// バイナリから文字列を検索
static const uint8_t *find_string(const uint8_t *data, uint32_t size, const char *str) {
    uint32_t str_len = strlen(str);
    for (uint32_t i = 0; i + str_len <= size; i++) {
        if (memcmp(data + i, str, str_len) == 0) return data + i;
    }
    return NULL;
}

// 文字列のVAからそれを参照する命令を探し、関数内のアドレスを抽出
// （簡易版: 文字列VAを含む関数を逆アセンブルして特定パターンを探す）
static uint32_t find_function_containing_va(csh handle, const uint8_t *data, uint32_t size,
                                            uint32_t base, uint32_t target_va) {
    // 全コードを逆アセンブルし、target_vaを参照するLDRを検索
    // 見つかったらその命令を含む関数の開始を推定
    cs_insn *insn;
    size_t count = cs_disasm(handle, data, size, base, 0, &insn);
    if (count == 0) return 0;

    uint32_t found_addr = 0;
    for (size_t i = 0; i < count; i++) {
        // LDR Rd, =literal を検索
        if (insn[i].id == ARM_INS_LDR) {
            // オペランド解析
            cs_arm *arm = &insn[i].detail->arm;
            if (arm->op_count == 2 && arm->operands[1].type == ARM_OP_MEM) {
                // リテラルプールアドレス
                uint64_t lit_addr = arm->operands[1].mem.disp;
                if (lit_addr == target_va) {
                    found_addr = insn[i].address;
                    break;
                }
            }
        }
    }
    cs_free(insn, count);
    return found_addr;
}

// BLX命令を検出してジャンプ先を取得
static int is_blx_reg(cs_insn *insn) {
    return insn->id == ARM_INS_BLX;
}

int extract_preloader_dl_ul(const uint8_t *data, uint32_t size, uint32_t base,
                            uint32_t *ptr_dl, uint32_t *ptr_ul) {
    const char *pat = "%s sync time %dms\n";
    const uint8_t *found = find_string(data, size, pat);
    if (!found) return -1;
    uint32_t str_va = base + (found - data);

    // Capstone初期化
    csh handle;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // 文字列参照を含む関数を探し、LDM命令から配列アドレスを取得
    // 実装の簡略化: 文字列VAを参照するLDRを検索し、その周辺のLDMを探す
    cs_insn *insn;
    size_t count = cs_disasm(handle, data, size, base, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        return -1;
    }

    uint32_t array_addr = 0;
    for (size_t i = 0; i < count; i++) {
        if (insn[i].id == ARM_INS_LDM) {
            // LDMのオペランドから配列ポインタを取得
            cs_arm *arm = &insn[i].detail->arm;
            if (arm->op_count >= 1 && arm->operands[0].type == ARM_OP_REG) {
                // レジスタの値を追跡する必要がある（簡易化）
                // ここでは直前のMOVW/MOVTを探す
                for (size_t j = i; j > 0 && j > i - 4; j--) {
                    if (insn[j].id == ARM_INS_MOVW && insn[j-1].id == ARM_INS_MOVT) {
                        // MOVW/MOVTの即値から配列アドレスを再構成
                        cs_arm *mw = &insn[j].detail->arm;
                        cs_arm *mt = &insn[j-1].detail->arm;
                        uint32_t low = mw->operands[1].imm;
                        uint32_t high = mt->operands[1].imm;
                        array_addr = (high << 16) | low;
                        break;
                    }
                }
            }
            if (array_addr) break;
        }
    }
    cs_free(insn, count);
    cs_close(&handle);

    if (!array_addr) return -1;

    // 配列からDL/ULを読み取る
    *ptr_dl = *(uint32_t*)(data + (array_addr - base));
    *ptr_ul = *(uint32_t*)(data + (array_addr - base) + 4);
    return 0;
}

int extract_lk_base(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *lk_base) {
    const char *pat = "UBOOT";
    const uint8_t *found = find_string(data, size, pat);
    if (!found) {
        pat = "%s Second Bootloader Load Failed";
        found = find_string(data, size, pat);
    }
    if (!found) return -1;
    uint32_t str_va = base + (found - data);

    // この文字列を参照する関数を探し、R3へのMOVW/MOVTからLKベースを取得
    csh handle;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn;
    size_t count = cs_disasm(handle, data, size, base, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        return -1;
    }

    uint32_t lk = 0;
    for (size_t i = 0; i < count; i++) {
        // 文字列を参照するLDRを探す
        if (insn[i].id == ARM_INS_LDR) {
            cs_arm *arm = &insn[i].detail->arm;
            if (arm->op_count == 2 && arm->operands[1].type == ARM_OP_MEM) {
                uint64_t lit = arm->operands[1].mem.disp;
                if (lit == str_va) {
                    // この命令の前後でR3への設定を探す
                    for (size_t j = i; j > 0 && j > i - 10; j--) {
                        if (insn[j].id == ARM_INS_MOVW && insn[j-1].id == ARM_INS_MOVT) {
                            cs_arm *mw = &insn[j].detail->arm;
                            cs_arm *mt = &insn[j-1].detail->arm;
                            if (mw->operands[0].reg == ARM_REG_R3 &&
                                mt->operands[0].reg == ARM_REG_R3) {
                                lk = (mt->operands[1].imm << 16) | mw->operands[1].imm;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (lk) break;
    }
    cs_free(insn, count);
    cs_close(&handle);

    if (!lk) return -1;
    *lk_base = lk;
    return 0;
}

int extract_bldr_jump(const uint8_t *data, uint32_t size, uint32_t base,
                      uint32_t *bldr_jump, uint32_t *da_addr) {
    const char *pat = "%s usbdl_jump_da: %x\n";
    const uint8_t *found = find_string(data, size, pat);
    if (!found) return -1;
    uint32_t str_va = base + (found - data);

    csh handle;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn;
    size_t count = cs_disasm(handle, data, size, base, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        return -1;
    }

    // 文字列を含む関数を特定し、その中のBLXを探す
    uint32_t func_start = 0, func_end = 0;
    for (size_t i = 0; i < count; i++) {
        if (insn[i].id == ARM_INS_LDR) {
            cs_arm *arm = &insn[i].detail->arm;
            if (arm->op_count == 2 && arm->operands[1].type == ARM_OP_MEM) {
                if (arm->operands[1].mem.disp == str_va) {
                    // 関数境界を推定（PUSH/POPで）
                    for (size_t j = i; j > 0; j--) {
                        if (insn[j].id == ARM_INS_PUSH) {
                            func_start = insn[j].address;
                            break;
                        }
                    }
                    for (size_t j = i; j < count; j++) {
                        if (insn[j].id == ARM_INS_POP) {
                            func_end = insn[j].address + insn[j].size;
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    if (!func_start || !func_end) {
        cs_free(insn, count);
        cs_close(&handle);
        return -1;
    }

    // 関数内のBLXを探し、最後のものをbldr_jumpとする
    uint32_t last_blx = 0;
    uint32_t last_blx_target = 0;
    for (size_t i = 0; i < count; i++) {
        if (insn[i].address >= func_start && insn[i].address < func_end) {
            if (insn[i].id == ARM_INS_BLX || insn[i].id == ARM_INS_BL) {
                last_blx = insn[i].address;
                // ターゲット取得
                cs_arm *arm = &insn[i].detail->arm;
                if (arm->op_count >= 1 && arm->operands[0].type == ARM_OP_IMM) {
                    last_blx_target = arm->operands[0].imm;
                }
            }
        }
    }

    cs_free(insn, count);
    cs_close(&handle);

    if (!last_blx) return -1;
    *bldr_jump = last_blx_target;

    // DAアドレスは4KB境界のリテラルから
    // 簡易: 関数内のリテラルプールから4KB境界の値を探す
    for (uint32_t off = func_start - base; off < func_end - base; off += 4) {
        uint32_t val = *(uint32_t*)(data + off);
        if ((val & 0xFFF) == 0 && val >= 0x40000000) {
            *da_addr = val;
            return 0;
        }
    }
    return -1;
}

int extract_mt_part_get_partition(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *addr) {
    const char *pat = "mt_part_get_partition";
    const uint8_t *found = find_string(data, size, pat);
    if (!found) return -1;
    uint32_t str_va = base + (found - data);

    csh handle;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn;
    size_t count = cs_disasm(handle, data, size, base, 0, &insn);
    uint32_t func_addr = 0;
    for (size_t i = 0; i < count; i++) {
        if (insn[i].id == ARM_INS_LDR) {
            cs_arm *arm = &insn[i].detail->arm;
            if (arm->op_count == 2 && arm->operands[1].type == ARM_OP_MEM) {
                if (arm->operands[1].mem.disp == str_va) {
                    func_addr = insn[i].address;
                    break;
                }
            }
        }
    }
    cs_free(insn, count);
    cs_close(&handle);

    if (!func_addr) return -1;
    // 関数の先頭を推定
    *addr = func_addr & ~1;
    return 0;
}

int extract_mt_part_generic_read(const uint8_t *data, uint32_t size, uint32_t base, uint32_t *addr) {
    const char *pat = "[mt_part_register_device]";
    const uint8_t *found = find_string(data, size, pat);
    if (!found) return -1;
    uint32_t str_va = base + (found - data);

    csh handle;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn;
    size_t count = cs_disasm(handle, data, size, base, 0, &insn);
    uint32_t read_addr = 0;
    for (size_t i = 0; i < count; i++) {
        if (insn[i].id == ARM_INS_STR) {
            cs_arm *arm = &insn[i].detail->arm;
            // STR Rd, [Rn, #0x10] を探す
            if (arm->op_count == 2 && arm->operands[1].type == ARM_OP_MEM) {
                int64_t disp = arm->operands[1].mem.disp;
                if (disp == 0x10) {
                    // ソースレジスタの値を追跡
                    // 簡易: 直前のMOVW/MOVTを探す
                    for (size_t j = i; j > 0 && j > i - 5; j--) {
                        if (insn[j].id == ARM_INS_MOVW && insn[j-1].id == ARM_INS_MOVT) {
                            cs_arm *mw = &insn[j].detail->arm;
                            cs_arm *mt = &insn[j-1].detail->arm;
                            if (mw->operands[0].reg == arm->operands[0].reg &&
                                mt->operands[0].reg == arm->operands[0].reg) {
                                read_addr = (mt->operands[1].imm << 16) | mw->operands[1].imm;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (read_addr) break;
    }
    cs_free(insn, count);
    cs_close(&handle);

    if (!read_addr) return -1;
    *addr = read_addr;
    return 0;
}
