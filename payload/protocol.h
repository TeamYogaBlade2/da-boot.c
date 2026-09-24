#ifndef PAYLOAD_PROTOCOL_H
#define PAYLOAD_PROTOCOL_H

#include <stdint.h>
#include "da_params.h"

// メッセージタイプ
#define MSG_ACK             0xA0
#define MSG_READ            0xA1
#define MSG_WRITE           0xA2
#define MSG_FLUSH_CACHE     0xA3
#define MSG_JUMP            0xA4
#define MSG_RESET           0xA5
#define MSG_HOOK            0xA6
#define MSG_GET_FREE_RANGE  0xA7
#define MSG_BLACKLIST_RANGE 0xA8
#define MSG_SET_PARAMS      0xA9

// レスポンスタイプ
#define RESP_ACK   'A'
#define RESP_NACK  'N'
#define RESP_RANGE 'R'
#define RESP_DATA  'D'
#define RESP_LOG   'L'

// エラーコード
#define PROTO_ERR_NOT_SUPPORTED      1
#define PROTO_ERR_UNREACHABLE        2
#define PROTO_ERR_DOWNLOAD_FORBIDDEN 3
#define PROTO_ERR_INVALID_PARAMS     4

// フックID
#define HOOK_MT_PART_GENERIC_READ    0
#define HOOK_FASTBOOT_INIT            1

// パラメータタイプ
#define PARAMS_PRELOADER  0
#define PARAMS_LK         1

// メッセージ構造体（ペイロード内部用）
typedef struct {
    uint8_t type;
    union {
        struct { uint32_t addr; uint32_t size; } read;
        struct { uint32_t addr; uint32_t size; } write;
        struct { uint32_t addr; uint32_t size; } flush_cache;
        struct { uint32_t addr; uint32_t r0; uint32_t r1; uint8_t has_r0; uint8_t has_r1; } jump;
        uint8_t hook;
        struct { uint32_t size; } get_free_range;
        struct { uint32_t start; uint32_t end; } blacklist;
        struct {
            uint8_t type;
            union {
                preloader_runner_params_t preloader;
                lk_runner_params_t lk;
            };
        } set_params;
    };
} message_t;

// レスポンス構造体
typedef struct {
    uint8_t type;      // RESP_ACK, RESP_NACK, RESP_RANGE, RESP_DATA
    uint8_t err;       // NACK時のエラーコード
    uint32_t addr;     // RANGE時のアドレス
} response_t;

// プロトコルコンテキスト
typedef struct {
    // シリアル通信関数（USB経由）
    int (*send)(const uint8_t *buf, uint32_t len);
    int (*recv)(uint8_t *buf, uint32_t len, uint32_t timeout_ms);
    uint8_t buf[512];
} protocol_t;

// プロトコル初期化
void protocol_init(protocol_t *p, int (*send_fn)(const uint8_t*, uint32_t),
                   int (*recv_fn)(uint8_t*, uint32_t, uint32_t));

// 送受信
int protocol_send_message(protocol_t *p, const message_t *msg);
int protocol_read_message(protocol_t *p, message_t *msg);
int protocol_send_response(protocol_t *p, const response_t *resp);
int protocol_read_response(protocol_t *p, response_t *resp);

#endif // PAYLOAD_PROTOCOL_H
