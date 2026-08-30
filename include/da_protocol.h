#ifndef DA_PROTOCOL_H
#define DA_PROTOCOL_H

#include <stdint.h>
#include "serial.h"        // serial_t の定義を使用
#include "da_params.h"     // preloader_runner_params_t, lk_runner_params_t の定義

// メッセージ種別
typedef enum {
    MSG_ACK = 0xA0,
    MSG_READ,
    MSG_WRITE,
    MSG_FLUSH_CACHE,
    MSG_JUMP,
    MSG_RESET,
    MSG_HOOK,
    MSG_GET_FREE_RANGE,
    MSG_BLACKLIST_RANGE,
    MSG_SET_PARAMS
} msg_type_t;

// フックID
typedef enum {
    HOOK_MT_PART_GENERIC_READ = 0
} hook_id_t;

// パラメータ種別
typedef enum {
    PARAMS_PRELOADER = 0,
    PARAMS_LK
} params_type_t;

// エラーコード
typedef enum {
    PROTO_ERR_NONE = 0,
    PROTO_ERR_NOT_SUPPORTED,
    PROTO_ERR_UNREACHABLE,
    PROTO_ERR_DOWNLOAD_FORBIDDEN,
    PROTO_ERR_INVALID_PARAMS
} proto_error_t;

// レスポンス
typedef struct {
    uint8_t type;  // 'A' = Ack, 'N' = Nack, 'R' = Range, 'D' = Data
    union {
        proto_error_t err;
        uint32_t addr;
    };
} response_t;

// メッセージ
typedef struct {
    msg_type_t type;
    union {
        struct { uint32_t addr; uint32_t size; } read;
        struct { uint32_t addr; uint32_t size; } write;
        struct { uint32_t addr; uint32_t size; } flush_cache;
        struct { uint32_t addr; uint32_t r0; uint32_t r1; int has_r0; int has_r1; } jump;
        hook_id_t hook;
        struct { uint32_t size; } get_free_range;
        struct { uint32_t start; uint32_t end; } blacklist;
        struct {
            params_type_t type;
            union {
                preloader_runner_params_t preloader;
                lk_runner_params_t lk;
            };
        } set_params;
    };
} message_t;

// プロトコルコンテキスト
typedef struct {
    serial_t *io;
    uint8_t buf[512];
} protocol_t;

// 初期化
void protocol_init(protocol_t *p, serial_t *io);

// 送受信
int protocol_send_message(protocol_t *p, const message_t *msg);
int protocol_read_message(protocol_t *p, message_t *msg);
int protocol_send_response(protocol_t *p, const response_t *resp);
int protocol_read_response(protocol_t *p, response_t *resp);

// ヘルパー
void message_init_ack(message_t *m);
void message_init_read(message_t *m, uint32_t addr, uint32_t size);
void message_init_write(message_t *m, uint32_t addr, uint32_t size);
void message_init_jump(message_t *m, uint32_t addr, uint32_t r0, uint32_t r1, int has_r0, int has_r1);
void message_init_hook(message_t *m, hook_id_t hook);
void message_init_get_free_range(message_t *m, uint32_t size);
void message_init_blacklist(message_t *m, uint32_t start, uint32_t end);
void message_init_set_params_preloader(message_t *m, preloader_runner_params_t *p);
void message_init_set_params_lk(message_t *m, lk_runner_params_t *p);

#endif // DA_PROTOCOL_H
