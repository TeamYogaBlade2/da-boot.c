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
static int g_usb_log_ready = 0;
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

static void usb_log_bytes(const uint8_t *data, uint32_t len) {
    uint8_t frame[1 + 240];

    while (len) {
        uint32_t chunk = len > 240 ? 240 : len;
        uint32_t frame_size = __builtin_bswap32(chunk + 1);

        frame[0] = RESP_LOG;
        memcpy(&frame[1], data, chunk);
        usb_send((const uint8_t *)&frame_size, sizeof(frame_size));
        usb_send(frame, chunk + 1);

        data += chunk;
        len -= chunk;
    }
}

static void uart_print(const char *s) {
    const char *start = s;
    while (*s) uart_putc(*s++);
    if (g_usb_log_ready && s != start)
        usb_log_bytes((const uint8_t *)start, (uint32_t)(s - start));
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
uint32_t mt_part_generic_read_hook(void *dev, uint32_t read_cb,
                                   uint32_t src_lo, uint32_t src_hi,
                                   uint8_t *dst, uint32_t size);
typedef struct {
    uint32_t r_offset;
    uint32_t r_info;
} elf32_rel_t;

#define R_ARM_RELATIVE 23u

extern uint8_t _image_start[];
extern uint8_t _rel_dyn_start[];
extern uint8_t _rel_dyn_end[];
extern uint8_t _bss_start[];
extern uint8_t _bss_end[];
extern uint8_t _stack_top[];

void main(uint32_t runtime_base);

/*
 * Switch to the final stack and branch to the relocated main().
 *
 * This is deliberately a tail branch: the old DA_ADDR stack must not remain
 * active after the relocation bootstrap has finished.
 */
static __attribute__((noreturn, noinline))
void enter_main(uint32_t entry, uint32_t runtime_base, uint32_t stack_top) {
    asm volatile(
        "mov r9, %[base]\n"
        "mov sp, %[stack]\n"
        "mov r0, %[base]\n"
        "bx  %[entry]\n"
        :
        : [stack] "r" (stack_top),
          [base]  "r" (runtime_base),
          [entry] "r" (entry)
        : "r0", "r9", "memory");

    __builtin_unreachable();
}

/*
 * The DA is initially downloaded to DA_ADDR.  The upstream implementation
 * relocates the PIE away from that staging area before entering the main
 * payload, and uses a separate stack range.  The startup code has already
 * applied the R_ARM_RELATIVE relocations to the original image, so when the
 * image is copied we adjust those already-relocated pointers by the
 * source->destination delta.
 */
__attribute__((noreturn, noinline))
void payload_bootstrap(uint32_t runtime_base) {
    payload_params_t *params = &g_params;

    /*
     * The MT6589 Preloader leaves the TOPRGU watchdog enabled when its
     * D5/JUMP_DA path hands control to the payload. Disable it before the
     * relocation/stack setup can be reset underneath us.
     *
     * The payload-side soc enum mirrors include/da_params.h:
     * SOC_MT6589 == 3.
     */
    if (params->soc == 3u) {
        volatile uint32_t * const wdt =
            (volatile uint32_t *)0x10000000u;
        uint32_t mode;

        wdt[2] = 0x1971u; /* WDT_RST */
        mode = wdt[0];
        mode &= ~1u;      /* WDT_MODE_EN */
        mode |= 0x22000000u; /* WDT_MODE_KEY */
        wdt[0] = mode;
        asm volatile("dsb sy\nisb sy" ::: "memory");
    }

    /*
     * The startup code relocates the GOT before entering C.  Linker
     * symbols referenced through that GOT therefore evaluate to runtime
     * addresses here, while the relocation entries themselves use
     * image-relative offsets.  Convert the runtime addresses back to
     * image-relative offsets before adding them to runtime_base/active_base.
     *
     * _image_start is explicitly zero in linker.ld, so keep it as zero
     * rather than depending on how the compiler materializes that symbol.
     */
    uint32_t image_start = 0;
    uint32_t bss_start = (uint32_t)_bss_start - runtime_base;
    uint32_t bss_end = (uint32_t)_bss_end - runtime_base;
    uint32_t rel_start = (uint32_t)_rel_dyn_start - runtime_base;
    uint32_t rel_end = (uint32_t)_rel_dyn_end - runtime_base;
    uint32_t raw_size = bss_start - image_start;
    uint32_t image_size = bss_end - image_start;
    uint32_t params_offset =
        (uint32_t)(uintptr_t)&g_params - runtime_base;
    uint32_t main_offset =
        (uint32_t)(uintptr_t)main - runtime_base;

    if (params->magic != MAGIC_DA || params->version != CURRENT_VERSION) {
        uart_print("Invalid payload parameters\n");
        while (1);
    }

    /*
     * The upstream payload searches for a relocation range first, then
     * checks whether the selected range overlaps the running image. On
     * MT6589 the DRAM range starts at 0x80000000 while the DA is normally
     * staged at 0x80001000, so the first free range may overlap the source.
     * Never copy an image over itself.
     */
    mem_range_t reloc_range;
    if (find_unused_range(params, image_size, &reloc_range) != 0) {
        uart_print("Failed to find relocation range\n");
        while (1);
    }

    uint32_t active_base = reloc_range.start;
    uint32_t runtime_end = runtime_base + image_size;
    uint32_t reloc_end = active_base + image_size;
    int overlaps = active_base < runtime_end && runtime_base < reloc_end;

    if (active_base != runtime_base && !overlaps) {
        /*
         * The original image has already had its GOT/RELATIVE relocations
         * fixed up for runtime_base. Copy the non-BSS portion, then adjust
         * each relocated pointer by the source-to-destination delta.
         */
        memcpy((void *)active_base, (const void *)runtime_base, raw_size);

        uint32_t delta = active_base - runtime_base;
        elf32_rel_t *rel =
            (elf32_rel_t *)(runtime_base + rel_start);
        elf32_rel_t *rel_limit =
            (elf32_rel_t *)(runtime_base + rel_end);

        for (; rel < rel_limit; rel++) {
            if ((rel->r_info & 0xffu) == R_ARM_RELATIVE) {
                uint32_t *target =
                    (uint32_t *)(active_base + rel->r_offset);
                *target += delta;
            }
        }

        /* The relocated text must be visible to the instruction cache. */
        flush_icache();
    } else {
        /*
         * The startup code already fixed the R_ARM_RELATIVE relocations for
         * runtime_base. Keep the image there when the candidate range
         * overlaps the running payload.
         */
        active_base = runtime_base;
    }

    /*
     * .bss is not file-backed by payload.bin, so explicitly create it in the
     * relocated image before entering C.
     */
    memset((void *)(active_base + bss_start),
           0, bss_end - bss_start);

    payload_params_t *active_params =
        (payload_params_t *)(active_base + params_offset);

    /*
     * Keep the running image out of subsequent host downloads.  The original
     * DA_ADDR range stays reserved in active_params because its bootstrap
     * range was copied together with the parameter block.
     */
    if (blacklist_dl(active_params,
                     active_base,
                     active_base + image_size) != 0) {
        uart_print("Failed to reserve relocated image\n");
        while (1);
    }

    mem_range_t stack_range;
    if (find_unused_range(active_params, 4096, &stack_range) != 0) {
        uart_print("Failed to find payload stack\n");
        while (1);
    }

    if (blacklist_dl(active_params,
                     stack_range.start,
                     stack_range.end) != 0) {
        uart_print("Failed to reserve payload stack\n");
        while (1);
    }

    /*
     * main() is Thumb code.  Preserve its Thumb bit when deriving its
     * relocated address from the runtime address used above.
     */
    uint32_t main_addr = (active_base + main_offset) | 1u;
    uint32_t stack_top = stack_range.end & ~7u;

    enter_main(main_addr, active_base, stack_top);
}

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
            if (g_has_preloader_params) {
                typedef void (*preloader_bldr_jump_fn_t)(
                    uint32_t addr, uint32_t arg1, uint32_t arg2);
                preloader_bldr_jump_fn_t fn =
                    (preloader_bldr_jump_fn_t)(uintptr_t)
                        (g_preloader_params.ptr_bldr_jump | 1u);
                fn(msg->jump.addr, msg->jump.r0, msg->jump.r1);
            } else {
                void (*fn)(uint32_t, uint32_t) =
                    (void(*)(uint32_t,uint32_t))msg->jump.addr;
                fn(msg->jump.r0, msg->jump.r1);
            }
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
                uart_print("Installing mt_part_generic_read hook at 0x");
                uart_print_hex(g_lk_params.ptr_mt_part_generic_read | 1u);
                uart_print("\n");
                if (interceptor_replace(g_lk_params.ptr_mt_part_generic_read | 1,
                                         (void*)mt_part_generic_read_hook) == 0) {
                    uart_print("mt_part_generic_read hook installed\n");
                    resp.type = RESP_ACK;
                } else {
                    uart_print("mt_part_generic_read hook failed\n");
                    resp.type = RESP_NACK;
                    resp.err = PROTO_ERR_NOT_SUPPORTED;
                }
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

/*
 * This MT6589 LK installs a six-argument read callback in dev + 0x10:
 *
 *     uint32_t read(part_dev_t *dev, uint32_t read_cb,
 *                   uint32_t src_lo, uint32_t src_hi,
 *                   uchar *dst, uint32_t size);
 *
 * mboot_android_load_bootimg() passes the current dev->read function
 * pointer itself as the second argument. Keep the argument positions
 * exactly as emitted by the stock LK; collapsing src into uint64_t would
 * shift every argument after r1 on 32-bit ARM.
 */
uint32_t mt_part_generic_read_hook(void *dev, uint32_t read_cb,
                                   uint32_t src_lo, uint32_t src_hi,
                                   uint8_t *dst, uint32_t size) {
    uint64_t src = ((uint64_t)src_hi << 32) | src_lo;
    static uint32_t log_count;

    if (!g_has_lk_params) return 0;

    if (log_count < 8) {
        uart_print("[mt_part_generic_read] src=0x");
        uart_print_hex(src_hi);
        uart_print_hex(src_lo);
        uart_print(" dst=0x");
        uart_print_hex((uint32_t)(uintptr_t)dst);
        uart_print(" size=0x");
        uart_print_hex(size);
        uart_print("\n");
        log_count++;
    }

    // 元の関数を呼び出す
    uint32_t (*orig)(void*, uint32_t, uint32_t, uint32_t, uint8_t*, uint32_t) =
        (void*)interceptor_original(g_lk_params.ptr_mt_part_generic_read);
    if (!orig) orig = (void*)g_lk_params.ptr_mt_part_generic_read;

    // mt_part_get_partition を呼び出し
    uint32_t (*get_part)(const char*) = (void*)g_lk_params.ptr_mt_part_get_partition;
    uint32_t *part = (uint32_t*)get_part("BOOTIMG");
    if (!part) {
        part = (uint32_t*)get_part("boot");
    }
    if (part) {
        /*
         * The returned partition descriptor has a common layout for this
         * LK.  +0x0c is the partition start block in 512-byte sectors;
         * the lookup name only selects the partition entry.
         */
        uint32_t startblk;
        memcpy(&startblk,
               (const uint8_t *)part + 0x0c,
               sizeof(startblk));
        uint64_t addr = (uint64_t)startblk << 9;
        if (src >= addr) {
            uint64_t delta64 = src - addr;

            /* The scratch image mirrors the whole LK read window, not just
             * the boot-image header. Let kernel/ramdisk reads hit it too. */
            if (delta64 < g_lk_params.bootimg_scratch_size) {
                uint32_t delta = (uint32_t)delta64;

                if (size <= g_lk_params.bootimg_scratch_size - delta) {
                    uart_print("[mt_part_generic_read] replacing boot.img"
                               " delta=0x");
                    uart_print_hex(delta);
                    uart_print(" size=0x");
                    uart_print_hex(size);
                    uart_print("\n");
                    memcpy(dst,
                           (void*)(g_lk_params.bootimg_scratch_addr + delta),
                           size);
                    return size;
                }
            }
        }
    }
    return orig(dev, read_cb, src_lo, src_hi, dst, size);
}

void main(uint32_t runtime_base) {
    (void)runtime_base;

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
    g_usb_log_ready = 1;

    uart_print("Payload starting...\n");

    // ヒープ初期化
    mem_range_t heap;
    if (find_unused_range(&g_params, 1024*1024, &heap) != 0) {
        uart_print("No heap\n");
        while(1);
    }
    bump_init((void*)heap.start, 1024*1024);
    if (blacklist_dl(&g_params, heap.start, heap.end) != 0) {
        uart_print("Failed to reserve heap\n");
        while(1);
    }

    uart_print("Ready\n");

    // メインループ
    while (1) {
        message_t msg;
        if (protocol_read_message(&proto, &msg) == 0) {
            handle_message(&proto, &msg);
        }
    }
}
