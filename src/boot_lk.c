#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "serial.h"
#include "mtk_protocol.h"
#include "da_protocol.h"
#include "soc_db.h"
#include "patcher.h"
#include "image.h"
#include "da_params.h"

// boot_arg構造体 (MT6589)
typedef struct {
    uint32_t magic;
    uint32_t boot_mode;
    uint32_t e_flag;
    uint32_t log_port;
    uint32_t log_baudrate;
    uint8_t  log_enable;
    uint8_t  reserved[3];
    uint32_t dram_rank_num;
    uint32_t dram_rank_size[4];
    uint32_t boot_reason;
    uint32_t meta_com_type;
    uint32_t meta_com_id;
    uint32_t boot_time;
    uint32_t da_info_addr;
    uint32_t da_info_arg1;
    uint32_t da_info_arg2;
    uint32_t sec_limit_magic;
    uint32_t sec_limit_mode;
} boot_arg_t;

#define BOOT_ARG_MAGIC 0x504c504c
#define BOOT_ARG_ADDR  0x800A0000

static void boot_arg_init(boot_arg_t *ba, uint32_t dram_size_per_rank, uint32_t dram_ranks) {
    memset(ba, 0, sizeof(*ba));
    ba->magic = BOOT_ARG_MAGIC;
    ba->boot_mode = 0; // NORMAL_BOOT
    ba->e_flag = 0;
    ba->log_port = 0x11006000; // MT6589 UART0
    ba->log_baudrate = 921600;
    ba->log_enable = 1;
    ba->dram_rank_num = dram_ranks;
    for (uint32_t i = 0; i < dram_ranks && i < 4; i++) {
        ba->dram_rank_size[i] = dram_size_per_rank;
    }
    ba->boot_reason = 4; // BR_TOOL_BY_PASS_PWK
    ba->boot_time = 1337;
}

// ファイル読み込み（再利用）
extern uint8_t *read_file(const char *path, uint32_t *size);

// Preloader解析（再利用）
extern int analyze_preloader(const uint8_t *data, uint32_t size, uint32_t base,
                             uint32_t *ptr_dl, uint32_t *ptr_ul,
                             uint32_t *bldr_jump, uint32_t *da_addr,
                             uint32_t *lk_base);

// ペイロード注入（再利用）
extern void inject_params(uint8_t *payload, uint32_t payload_size,
                          const payload_params_t *params);

int run_lk_mode(serial_t *s, const soc_info_t *soc, const char *payload_path,
                const char *preloader_path, const char *lk_path,
                const char *input_path, uint32_t input_addr,
                const char *kernel_path, const char *ramdisk_path,
                uint32_t dram_size_per_rank, uint32_t dram_ranks) {
    printf("LK mode for %s\n", soc->name);

    if (!lk_path) {
        fprintf(stderr, "LK path required for LK mode\n");
        return -1;
    }
    if (!dram_size_per_rank || !dram_ranks) {
        fprintf(stderr, "DRAM size and ranks required for LK mode\n");
        return -1;
    }

    // Preloader読み込みと解析
    uint32_t pl_size;
    uint8_t *pl_data = read_file(preloader_path, &pl_size);
    if (!pl_data) {
        fprintf(stderr, "Failed to read preloader\n");
        return -1;
    }
    /*
    uint32_t ptr_dl, ptr_ul, bldr_jump, da_addr, lk_base;
    if (analyze_preloader(pl_data, pl_size, soc->dram_base,
                          &ptr_dl, &ptr_ul, &bldr_jump, &da_addr, &lk_base) != 0) {
        fprintf(stderr, "Preloader analysis failed\n");
        free(pl_data);
        return -1;
    }
    */

    // $ sha256sum data/preloader_blade10_row_wifi.bin
    // 127b16dccd19716ab53436780671882f2c6e4ff7333dbb976a2001d5da8b48ab  data/preloader_blade10_row_wifi.bin
    uint32_t ptr_dl = 0x12004935;
    uint32_t ptr_ul = 0x12004987;
    uint32_t bldr_jump = 0x12004FC1;
    uint32_t da_addr = 0x80001000;
    uint32_t lk_base = soc->lk_base_hint; // 0x81E00000

    free(pl_data);

    // LK読み込みと解析
    uint32_t lk_size;
    uint8_t *lk_data = read_file(lk_path, &lk_size);
    if (!lk_data) {
        fprintf(stderr, "Failed to read LK\n");
        return -1;
    }
    if (lk_base == 0) lk_base = soc->lk_base_hint;

    uint32_t mt_part_generic_read, mt_part_get_partition;
    if (extract_mt_part_generic_read(lk_data, lk_size, lk_base, &mt_part_generic_read) != 0) {
        fprintf(stderr, "Failed to extract mt_part_generic_read\n");
        free(lk_data);
        return -1;
    }
    if (extract_mt_part_get_partition(lk_data, lk_size, lk_base, &mt_part_get_partition) != 0) {
        fprintf(stderr, "Failed to extract mt_part_get_partition\n");
        free(lk_data);
        return -1;
    }
    printf("mt_part_generic_read: 0x%x\n", mt_part_generic_read);
    printf("mt_part_get_partition: 0x%x\n", mt_part_get_partition);

    // ペイロード読み込みと注入
    uint32_t payload_size;
    uint8_t *payload = read_file(payload_path, &payload_size);
    if (!payload) {
        fprintf(stderr, "Failed to read payload\n");
        free(lk_data);
        return -1;
    }
    payload_params_t params;
    payload_params_init(&params, soc->dram_base, soc->dram_base + 0x40000000,
                        ptr_dl, ptr_ul, SOC_MT6589);
    inject_params(payload, payload_size, &params);

    // DA送信とジャンプ
    printf("Sending payload...\n");
    if (mtk_send_da(s, soc->da_ram_addr, payload, payload_size) != 0) {
        fprintf(stderr, "Failed to send DA\n");
        free(payload);
        free(lk_data);
        return -1;
    }
    if (mtk_jump_da(s, soc->da_ram_addr) != 0) {
        fprintf(stderr, "Failed to jump DA\n");
        free(payload);
        free(lk_data);
        return -1;
    }

    // RPC開始
    protocol_t proto;
    protocol_init(&proto, s);
    message_t msg;
    if (protocol_read_message(&proto, &msg) != 0 || msg.type != MSG_ACK) {
        fprintf(stderr, "No ACK from payload\n");
        free(payload);
        free(lk_data);
        return -1;
    }
    message_init_ack(&msg);
    protocol_send_message(&proto, &msg);

    // Preloader params
    preloader_runner_params_t pl_params;
    pl_params.ptr_bldr_jump = bldr_jump;
    message_init_set_params_preloader(&msg, &pl_params);
    protocol_send_message(&proto, &msg);
    response_t resp;
    protocol_read_response(&proto, &resp);

    // boot.img準備とアップロード
    uint32_t bootimg_addr = 0;
    uint32_t bootimg_size = 0;
    uint8_t *bootimg_data = NULL;

    if (kernel_path) {
        // mkbootimgを呼び出す（簡易: 外部コマンドに依存）
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
                 "mkbootimg --kernel %s --ramdisk %s --base 0x%x --kernel_offset 0x8000 "
                 "--ramdisk_offset 0x4000000 -o /tmp/boot.img",
                 kernel_path, ramdisk_path ? ramdisk_path : "/dev/null", soc->dram_base);
        printf("Running: %s\n", cmd);
        if (system(cmd) != 0) {
            fprintf(stderr, "mkbootimg failed\n");
            free(payload);
            free(lk_data);
            return -1;
        }
        bootimg_data = read_file("/tmp/boot.img", &bootimg_size);
        if (!bootimg_data) {
            fprintf(stderr, "Failed to read boot.img\n");
            free(payload);
            free(lk_data);
            return -1;
        }
    } else if (input_path) {
        bootimg_data = read_file(input_path, &bootimg_size);
        if (!bootimg_data) {
            fprintf(stderr, "Failed to read boot.img\n");
            free(payload);
            free(lk_data);
            return -1;
        }
    } else {
        fprintf(stderr, "No boot image provided\n");
        free(payload);
        free(lk_data);
        return -1;
    }

    // 空きメモリ取得
    message_init_get_free_range(&msg, bootimg_size);
    protocol_send_message(&proto, &msg);
    if (protocol_read_response(&proto, &resp) != 0 || resp.type != 'R') {
        fprintf(stderr, "Failed to get free range\n");
        free(bootimg_data);
        free(payload);
        free(lk_data);
        return -1;
    }
    bootimg_addr = resp.addr;
    printf("boot.img at 0x%x (%u bytes)\n", bootimg_addr, bootimg_size);

    // アップロード
    const uint32_t CHUNK = 256 * 1024;
    for (uint32_t off = 0; off < bootimg_size; off += CHUNK) {
        uint32_t chunk = bootimg_size - off > CHUNK ? CHUNK : bootimg_size - off;
        message_init_write(&msg, bootimg_addr + off, chunk);
        protocol_send_message(&proto, &msg);
        uint32_t size_be = __builtin_bswap32(chunk);
        serial_write(s, (uint8_t*)&size_be, 4);
        serial_write(s, bootimg_data + off, chunk);
        protocol_read_response(&proto, &resp);
    }
    free(bootimg_data);

    // ブラックリスト
    message_init_blacklist(&msg, bootimg_addr, bootimg_addr + bootimg_size);
    protocol_send_message(&proto, &msg);
    protocol_read_response(&proto, &resp);

    // LKパラメータ設定
    lk_runner_params_t lk_params;
    lk_params.ptr_mt_part_generic_read = mt_part_generic_read | 1; // Thumb
    lk_params.ptr_mt_part_get_partition = mt_part_get_partition | 1;
    lk_params.bootimg_scratch_addr = bootimg_addr;
    message_init_set_params_lk(&msg, &lk_params);
    protocol_send_message(&proto, &msg);
    protocol_read_response(&proto, &resp);

    // フック設定
    message_init_hook(&msg, HOOK_MT_PART_GENERIC_READ);
    protocol_send_message(&proto, &msg);
    protocol_read_response(&proto, &resp);

    // LKアップロード
    printf("Uploading LK to 0x%x...\n", lk_base);
    for (uint32_t off = 0; off < lk_size; off += CHUNK) {
        uint32_t chunk = lk_size - off > CHUNK ? CHUNK : lk_size - off;
        message_init_write(&msg, lk_base + off, chunk);
        protocol_send_message(&proto, &msg);
        uint32_t size_be = __builtin_bswap32(chunk);
        serial_write(s, (uint8_t*)&size_be, 4);
        serial_write(s, lk_data + off, chunk);
        protocol_read_response(&proto, &resp);
    }
    free(lk_data);

    // Boot arg準備とアップロード
    boot_arg_t boot_arg;
    boot_arg_init(&boot_arg, dram_size_per_rank, dram_ranks);
    printf("Uploading boot arg to 0x%x...\n", BOOT_ARG_ADDR);
    message_init_write(&msg, BOOT_ARG_ADDR, sizeof(boot_arg_t));
    protocol_send_message(&proto, &msg);
    uint32_t size_be = __builtin_bswap32(sizeof(boot_arg_t));
    serial_write(s, (uint8_t*)&size_be, 4);
    serial_write(s, (uint8_t*)&boot_arg, sizeof(boot_arg_t));
    protocol_read_response(&proto, &resp);

    // LKへジャンプ
    printf("Jumping to LK at 0x%x with boot arg at 0x%x\n", lk_base, BOOT_ARG_ADDR);
    message_init_jump(&msg, lk_base, BOOT_ARG_ADDR, sizeof(boot_arg_t), 1, 1);
    protocol_send_message(&proto, &msg);
    protocol_read_response(&proto, &resp);

    free(payload);
    return 0;
}
