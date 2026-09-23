#include <stdint.h>
#include "libc_min.h"
#include "da_params.h"
#include "protocol.h"
#include "bump_alloc.h"
#include "cache.h"
#include "interceptor.h"
#include "usb.h"

// UART (MT6589: 0x11006000)
#define UART0_BASE 0x11006000

__attribute__((section(".params"), used, aligned(4)))
payload_params_t g_params = {
    .magic = MAGIC_DA,
};

// USB通信関数（Preloaderから提供される）
static uint32_t g_usb_send_fn;
static uint32_t g_usb_recv_fn;

// グローバル状態
static preloader_runner_params_t g_preloader_params;
static lk_runner_params_t g_lk_params;
static int g_has_preloader_params = 0;
static int g_has_lk_params = 0;

static void uart_putc(char c) {
    volatile uint32_t *status = (volatile uint32_t*)(UART0_BASE + 0x14);
    volatile uint32_t *data = (volatile uint32_t*)(UART0_BASE + 0x00);
    for (uint32_t i = 0; i < 100000; i++) {
        if (*status & 0x20) {
            *data = c;
            return;
        }
    }
}

static void uart_print(const char *s) {
    while (*s) uart_putc(*s++);
}

static void uart_print_hex(uint32_t v) {
    char buf[9];
    for (int i = 7; i >= 0; i--) {
        uint8_t nib = (v >> (i*4)) & 0xF;
        buf[7-i] = nib < 10 ? '0' + nib : 'A' + nib - 10;
    }
    buf[8] = '\0';
    uart_print(buf);
}

// USB送受信ラッパー
static int usb_send_wrapper(const uint8_t *buf, uint32_t len) {
    return usb_send(buf, len);
}

static int usb_recv_wrapper(uint8_t *buf, uint32_t len, uint32_t timeout) {
    return usb_recv(buf, len, timeout);
}

// LKフック関数
uint32_t mt_part_generic_read_hook(void *dev, uint64_t src, uint8_t *dst, uint32_t size);

static void handle_message(protocol_t *proto, message_t *msg) {
    response_t resp;
    resp.type = RESP_ACK;
    resp.err = 0;
    resp.addr = 0;

    switch (msg->type) {
        case MSG_ACK:
            resp.type = RESP_ACK;
            break;
        case MSG_READ: {
            // データ送信
            uint8_t *data = (uint8_t*)msg->read.addr;
            uint32_t size = msg->read.size;
            // レスポンスとしてデータを直接送る（特殊）
            uint8_t buf[512];
            uint32_t len = 0;
            buf[len++] = RESP_DATA;
            memcpy(&buf[len], data, size); len += size;
            uint32_t size_be = __builtin_bswap32(len);
            usb_send((uint8_t*)&size_be, 4);
            usb_send(buf, len);
            return;
        }
        case MSG_WRITE: {
            // データ受信
            uint8_t *data = (uint8_t*)msg->write.addr;
            uint32_t size = msg->write.size;
            // 長さ受信
            uint8_t size_buf[4];
            usb_recv(size_buf, 4, 0);
            uint32_t recv_len = __builtin_bswap32(*(uint32_t*)size_buf);
            usb_recv(data, recv_len, 0);
            resp.type = RESP_ACK;
            break;
        }
        case MSG_FLUSH_CACHE:
            flush_dcache(msg->flush_cache.addr, msg->flush_cache.size);
            flush_icache();
            resp.type = RESP_ACK;
            break;
        case MSG_JUMP: {
            void (*fn)(uint32_t, uint32_t) = (void(*)(uint32_t,uint32_t))msg->jump.addr;
            fn(msg->jump.r0, msg->jump.r1);
            resp.type = RESP_NACK;
            resp.err = PROTO_ERR_UNREACHABLE;
            break;
        }
        case MSG_RESET: {
            volatile uint32_t *wdt = (volatile uint32_t*)(0x10000000 + 0x14);
            *wdt = 0x1209;
            while(1);
        }
        case MSG_HOOK:
            if (msg->hook == HOOK_MT_PART_GENERIC_READ && g_has_lk_params) {
                interceptor_replace(g_lk_params.ptr_mt_part_generic_read | 1,
                                    (void*)mt_part_generic_read_hook);
                resp.type = RESP_ACK;
            } else {
                resp.type = RESP_NACK;
                resp.err = PROTO_ERR_NOT_SUPPORTED;
            }
            break;
        case MSG_GET_FREE_RANGE: {
            mem_range_t range;
            if (find_unused_range(&g_params, msg->get_free_range.size, &range) == 0) {
                resp.type = RESP_RANGE;
                resp.addr = range.start;
            } else {
                resp.type = RESP_RANGE;
                resp.addr = 0; // null相当
            }
            break;
        }
        case MSG_BLACKLIST_RANGE:
            if (blacklist_dl(&g_params, msg->blacklist.start, msg->blacklist.end) == 0) {
                resp.type = RESP_ACK;
            } else {
                resp.type = RESP_NACK;
                resp.err = PROTO_ERR_NOT_SUPPORTED;
            }
            break;
        case MSG_SET_PARAMS:
            if (msg->set_params.type == PARAMS_PRELOADER) {
                g_preloader_params = msg->set_params.preloader;
                g_has_preloader_params = 1;
                resp.type = RESP_ACK;
            } else if (msg->set_params.type == PARAMS_LK) {
                g_lk_params = msg->set_params.lk;
                g_has_lk_params = 1;
                resp.type = RESP_ACK;
            } else {
                resp.type = RESP_NACK;
                resp.err = PROTO_ERR_INVALID_PARAMS;
            }
            break;
        default:
            resp.type = RESP_NACK;
            resp.err = PROTO_ERR_NOT_SUPPORTED;
    }

    protocol_send_response(proto, &resp);
}

uint32_t mt_part_generic_read_hook(void *dev, uint64_t src, uint8_t *dst, uint32_t size) {
    if (!g_has_lk_params) return 0;

    // 元の関数を呼び出す
    uint32_t (*orig)(void*, uint64_t, uint8_t*, uint32_t) =
        (void*)interceptor_original(g_lk_params.ptr_mt_part_generic_read);
    if (!orig) orig = (void*)g_lk_params.ptr_mt_part_generic_read;

    // mt_part_get_partition を呼び出し
    uint32_t (*get_part)(const char*) = (void*)g_lk_params.ptr_mt_part_get_partition;
    uint32_t *part = (uint32_t*)get_part("BOOTIMG");
    int offset = 12; // MT6589確認済み
    if (!part) {
        part = (uint32_t*)get_part("boot");
        offset = 0;
    }
    if (part) {
        uint64_t addr = ((uint64_t)part[offset/4]) << 9;
        uint32_t delta = (uint32_t)(src - addr);
        if (delta <= 0x1000) {
            memcpy(dst, (void*)(g_lk_params.bootimg_scratch_addr + delta), size);
            return size;
        }
    }
    return orig(dev, src, dst, size);
}

void main(uint32_t runtime_base) {
    // BSS初期化
    extern uint8_t _bss_start[], _bss_end[], _stack_top[];
    uint32_t bss_start = (uint32_t)_bss_start;
    uint32_t bss_end = (uint32_t)_bss_end;
    uint32_t stack_top = runtime_base + (uint32_t)_stack_top;
    memset((void *)(runtime_base + bss_start), 0, bss_end - bss_start);

    /*
     * The payload image and its bootstrap stack occupy the DA execution
     * address.  Keep the allocator/download path from returning that range,
     * otherwise an upload can overwrite the running payload.
     */
    if (blacklist_dl(&g_params, runtime_base, stack_top) != 0) {
        uart_print("Failed to reserve payload memory\n");
        while (1);
    }

    // パラメータ検証
    if (g_params.magic != MAGIC_DA) {
        uart_print("Invalid magic\n");
        while(1);
    }

    // USB関数ポインタ設定
    usb_init(g_params.ptr_ul, g_params.ptr_dl);

    // プロトコル初期化
    protocol_t proto;
    protocol_init(&proto, usb_send_wrapper, usb_recv_wrapper);

    // ACK送信
    message_t ack;
    ack.type = MSG_ACK;
    if (protocol_send_message(&proto, &ack) != 0) {
        uart_print("Initial ACK failed\n");
        while(1);
    }

    // ホスト側は MSG_ACK を返す
    message_t host_ack;
    if (protocol_read_message(&proto, &host_ack) != 0 ||
        host_ack.type != MSG_ACK) {
        uart_print("Handshake failed\n");
        while(1);
    }

    uart_print("Payload starting...\n");

    // ヒープ初期化
    mem_range_t heap;
    if (find_unused_range(&g_params, 1024*1024, &heap) != 0) {
        uart_print("No heap\n");
        while(1);
    }
    bump_init((void*)heap.start, 1024*1024);

    uart_print("Ready\n");

    // メインループ
    while (1) {
        message_t msg;
        if (protocol_read_message(&proto, &msg) == 0) {
            handle_message(&proto, &msg);
        }
    }
}
