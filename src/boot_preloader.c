#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "serial.h"
#include "mtk_protocol.h"
#include "da_protocol.h"
#include "soc_db.h"
#include "patcher.h"
#include "da_params.h"
#include "util.h"
#include "boot.h"

static soc_type_t payload_soc_type(const soc_info_t *soc) {
    if (soc->hw_code == soc_mt6589.hw_code)
        return SOC_MT6589;
    if (soc->hw_code == soc_mt6572.hw_code)
        return SOC_MT6572;
    if (soc->hw_code == soc_mt6582.hw_code)
        return SOC_MT6582;
    if (soc->hw_code == soc_mt6595.hw_code)
        return SOC_MT6595;
    return SOC_UNKNOWN;
}

int run_preloader_mode(serial_t *s, const soc_info_t *soc, const char *payload_path,
                       const char *preloader_path,
                       const upload_file_t *inputs, size_t input_count,
                       uint32_t preloader_addr_hint, uint32_t jump_addr) {
    printf("Preloader mode for %s\n", soc->name);

    // Preloaderバイナリ読み込み
    uint32_t pl_size;
    uint8_t *pl_data = read_file(preloader_path, &pl_size);
    if (!pl_data) {
        fprintf(stderr, "Failed to read preloader\n");
        return -1;
    }

    // ペイロード読み込み
    uint32_t payload_size;
    uint8_t *payload = read_file(payload_path, &payload_size);
    if (!payload) {
        fprintf(stderr, "Failed to read payload\n");
        free(pl_data);
        return -1;
    }

    uint32_t ptr_dl, ptr_ul, bldr_jump, da_addr, lk_base;
    if (analyze_preloader(pl_data, pl_size,
                          preloader_addr_hint ? preloader_addr_hint : soc->dram_base,
                          &ptr_dl, &ptr_ul, &bldr_jump, &da_addr, &lk_base) != 0) {
        fprintf(stderr, "Preloader analysis failed\n");
        free(pl_data);
        free(payload);
        return -1;
    }

    printf("ptr_dl: 0x%x, ptr_ul: 0x%x\n", ptr_dl, ptr_ul);
    printf("bldr_jump: 0x%x, da_addr: 0x%x\n", bldr_jump, da_addr);
    if (lk_base) printf("lk_base: 0x%x\n", lk_base);

    // PayloadParams初期化
    payload_params_t params;
    payload_params_init(&params, soc->dram_base, soc->dram_base + 0x40000000,
                        ptr_dl, ptr_ul, payload_soc_type(soc));

    // Preloader runner params
    preloader_runner_params_t pl_params;
    pl_params.ptr_bldr_jump = bldr_jump;

    // ペイロードにパラメータ注入
    if (inject_params(payload, payload_size, &params) != 0) {
        fprintf(stderr, "Payload does not contain a parameter marker\n");
        free(pl_data);
        free(payload);
        return -1;
    }

    if (input_count == 0 && jump_addr == 0) {
        printf("DA is ready; no final jump requested\n");
        free(pl_data);
        free(payload);
        return 0;
    }

    // DA送信（Preloaderはアドレスを無視してCFG_DA_RAM_ADDRに配置）
    printf("Sending payload to 0x%x...\n", da_addr);
    if (mtk_send_da(s, da_addr, payload, payload_size) != 0) {
        fprintf(stderr, "Failed to send DA\n");
        free(pl_data);
        free(payload);
        return -1;
    }

    // ジャンプ
    printf("Jumping to DA...\n");
    if (mtk_jump_da(s, da_addr) != 0) {
        fprintf(stderr, "Failed to jump DA\n");
        free(pl_data);
        free(payload);
        return -1;
    }

    // RPCプロトコル開始
    printf("Starting RPC protocol...\n");
    protocol_t proto;
    protocol_init(&proto, s);

    // 同期
    message_t msg;
    if (protocol_read_message(&proto, &msg) != 0 || msg.type != MSG_ACK) {
        fprintf(stderr, "No ACK from payload\n");
        free(pl_data);
        free(payload);
        return -1;
    }
    message_init_ack(&msg);
    protocol_send_message(&proto, &msg);

    // Preloader params設定
    message_init_set_params_preloader(&msg, &pl_params);
    if (protocol_send_message(&proto, &msg) != 0) {
        fprintf(stderr, "Failed to send preloader params\n");
        free(pl_data);
        free(payload);
        return -1;
    }
    response_t resp;
    if (protocol_read_response(&proto, &resp) != 0 || resp.type != 'A') {
        fprintf(stderr, "Failed to set preloader params\n");
        free(pl_data);
        free(payload);
        return -1;
    }

    // ファイルアップロード
    for (size_t input_index = 0; input_index < input_count; input_index++) {
        const upload_file_t *input = &inputs[input_index];
        uint32_t input_size;
        uint8_t *input_data = read_file(input->path, &input_size);
        if (!input_data) {
            fprintf(stderr, "Failed to read input file\n");
            free(pl_data);
            free(payload);
            return -1;
        }
        if (input->addr > UINT32_MAX - input_size) {
            fprintf(stderr, "Input range overflows 32-bit address space\n");
            free(input_data);
            free(pl_data);
            free(payload);
            return -1;
        }
        printf("Uploading to 0x%x (%u bytes)...\n", input->addr, input_size);

        // チャンク送信
        const uint32_t CHUNK = 256 * 1024;
        for (uint32_t off = 0; off < input_size; off += CHUNK) {
            uint32_t chunk = input_size - off > CHUNK ? CHUNK : input_size - off;
            message_init_write(&msg, input->addr + off, chunk);
            if (protocol_send_message(&proto, &msg) != 0) {
                fprintf(stderr, "Failed to send write request\n");
                free(input_data);
                free(pl_data);
                free(payload);
                return -1;
            }
            // データ本体送信
            uint32_t size_be = __builtin_bswap32(chunk);
            if (serial_write(s, (uint8_t*)&size_be, 4) != 0 ||
                serial_write(s, input_data + off, chunk) != 0 ||
                protocol_read_response(&proto, &resp) != 0 ||
                resp.type != RESP_ACK) {
                fprintf(stderr, "Write failed\n");
                free(input_data);
                free(pl_data);
                free(payload);
                return -1;
            }
        }
        free(input_data);

        // ブラックリスト登録
        message_init_blacklist(&msg, input->addr, input->addr + input_size);
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to blacklist uploaded range\n");
            free(pl_data);
            free(payload);
            return -1;
        }
    }

    // ジャンプ
    printf("Jumping to 0x%x\n", jump_addr);
    message_init_jump(&msg, jump_addr, 0, 0, 0, 0);
    protocol_send_message(&proto, &msg);
    protocol_read_response(&proto, &resp);

    free(pl_data);
    free(payload);
    return 0;
}
