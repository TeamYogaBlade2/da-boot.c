#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "serial.h"
#include "mtk_protocol.h"
#include "da_protocol.h"
#include "soc_db.h"
#include "patcher.h"
#include "image.h"
#include "da_params.h"
#include "util.h"
#include "boot.h"

/* MediaTek AP image header used by stock LK for KERNEL/ROOTFS. */
#define MTK_IMAGE_MAGIC       0x58881688u
#define MTK_IMAGE_EXT_MAGIC   0x58891689u
#define MTK_IMAGE_HEADER_SIZE 0x200u
#define MTK_IMAGE_ALIGN_SIZE  0x10u
#define MTK_BOOT_PAGE_ALIGN(size) (((size) + 0x7ffu) & ~0x7ffu)
#define MT6589_LK_BOOTIMG_READ_SLACK 0x1000u

/* Fixed load addresses used by the Blade 10 KitKat LK. */
#define MT6589_LK_KERNEL_ADDR  0x80008000u
#define MT6589_LK_RAMDISK_ADDR 0x84000000u

/* Exact Blade 10 KitKat LK offsets relative to lk_base = 0x81E00000. */
#define MT6589_LK_FASTBOOT_INIT_OFFSET     0x1ee7cu
#define MT6589_LK_FASTBOOT_REGISTER_OFFSET 0x1ea9cu
#define MT6589_LK_FASTBOOT_OKAY_OFFSET     0x1ee6cu
#define MT6589_LK_FASTBOOT_FAIL_OFFSET     0x1ecd4u
#define MT6589_LK_UDC_STOP_OFFSET          0x0e0b8u
#define MT6589_LK_MTK_WDT_INIT_OFFSET      0x15718u
#define MT6589_LK_BOOT_LINUX_OFFSET        0x1e3bcu
#define MT6589_LK_BOOT_MODE_OFFSET         0x4d1c4u
#define MT6589_LK_MACHTYPE                 0x19bdu

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t data_size;
    char name[32];
    uint32_t addr;
    uint32_t mode;
    uint32_t ext_magic;
    uint32_t header_size;
    uint32_t header_version;
    uint32_t image_type;
    uint32_t image_list_end;
    uint32_t align_size;
    uint32_t data_size_ext;
    uint32_t addr_ext;
    uint32_t scrambled;
    uint8_t reserved[428];
} mtk_image_header_t;

_Static_assert(sizeof(mtk_image_header_t) == MTK_IMAGE_HEADER_SIZE,
               "unexpected MediaTek image header size");

static int write_mtk_image(const char *path, const char *name,
                           const uint8_t *data, uint32_t size) {
    FILE *fp;
    mtk_image_header_t hdr;
    size_t name_len;

    if (!path || !name || (!data && size))
        return -1;

    name_len = strlen(name);
    if (name_len > sizeof(hdr.name))
        return -1;

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = MTK_IMAGE_MAGIC;
    hdr.data_size = size;
    memcpy(hdr.name, name, name_len);
    hdr.ext_magic = MTK_IMAGE_EXT_MAGIC;
    hdr.header_size = MTK_IMAGE_HEADER_SIZE;
    hdr.header_version = 1;
    hdr.image_type = 0;       /* ImageKind::Ap(APBin) */
    hdr.image_list_end = 1;
    hdr.align_size = MTK_IMAGE_ALIGN_SIZE;

    fp = fopen(path, "wb");
    if (!fp)
        return -1;

    if (fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr) ||
        (size && fwrite(data, 1, size, fp) != size)) {
        fclose(fp);
        unlink(path);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int create_temp_path(char *path) {
    int fd;

    fd = mkstemp(path);
    if (fd < 0)
        return -1;
    if (close(fd) != 0) {
        unlink(path);
        return -1;
    }
    return 0;
}

static int wrap_file_as_mtk_image(const char *input_path,
                                  const char *output_path,
                                  const char *name, uint32_t *data_size) {
    uint32_t size;
    uint8_t *data;
    int ret;

    data = read_file(input_path, &size);
    if (!data)
        return -1;

    ret = write_mtk_image(output_path, name, data, size);
    if (ret == 0 && data_size)
        *data_size = size;
    free(data);
    return ret;
}

/* Build a normal Android boot image for fastboot. Unlike storage-mode LK,
 * fastboot consumes raw kernel/ramdisk data and does not need MTK partition
 * headers around the components. */
static int prepare_fastboot_bootimg(const char *kernel_path,
                                    const char *ramdisk_path,
                                    const char *input_path,
                                    uint32_t dram_base,
                                    char *output_path,
                                    size_t output_size,
                                    int *owned) {
    char empty_ramdisk_path[] = "/tmp/da-boot-fastboot-ramdisk-XXXXXX";
    char bootimg_path[] = "/tmp/da-boot-fastboot-XXXXXX";
    char cmd[1024];
    const char *ramdisk_input = ramdisk_path;
    int success = 0;

    if (!output_path || output_size == 0 || !owned)
        return -1;
    output_path[0] = '\0';
    *owned = 0;

    if (input_path) {
        if (snprintf(output_path, output_size, "%s", input_path) >=
            (int)output_size)
            return -1;
        return 0;
    }
    if (!kernel_path)
        return -1;

    if (!ramdisk_input) {
        if (create_temp_path(empty_ramdisk_path) != 0)
            return -1;
        ramdisk_input = empty_ramdisk_path;
    }

    if (create_temp_path(bootimg_path) != 0)
        goto cleanup;

    snprintf(cmd, sizeof(cmd),
             "mkbootimg --kernel %s --ramdisk %s --base 0x%x "
             "--kernel_offset 0x8000 --ramdisk_offset 0x4000000 "
             "--pagesize 2048 -o %s",
             kernel_path, ramdisk_input, dram_base, bootimg_path);
    printf("Running: %s\n", cmd);
    if (system(cmd) != 0)
        goto cleanup;

    if (snprintf(output_path, output_size, "%s", bootimg_path) >=
        (int)output_size)
        goto cleanup;

    success = 1;
    *owned = 1;

cleanup:
    if (!ramdisk_path)
        unlink(empty_ramdisk_path);
    if (!success)
        unlink(bootimg_path);
    return success ? 0 : -1;
}

static int run_host_fastboot_boot(const char *bootimg_path) {
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execlp("fastboot", "fastboot", "boot", bootimg_path,
               (char *)NULL);
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;

    if (WIFSIGNALED(status)) {
        fprintf(stderr, "fastboot terminated by signal %d\n",
                WTERMSIG(status));
    } else if (WIFEXITED(status)) {
        fprintf(stderr, "fastboot exited with status %d\n",
                WEXITSTATUS(status));
    }
    return -1;
}

/*
 * MT6589 KitKat LK does not read exactly the Android boot image size.
 *
 * mboot_android_load_bootimg() uses:
 *
 *     start = partition_start + 0x800
 *     size  = (kernel_pages + ramdisk_pages + 2) * 0x800
 *
 * The standard mkbootimg output is two 0x800 pages shorter than that
 * source window.  Keep zero-filled backing storage for the extra 0x1000
 * bytes so the DA-side read hook never accesses beyond the uploaded
 * scratch image.
 */
static int pad_lk_bootimg_read_window(uint8_t **data, uint32_t *size) {
    uint32_t padded_size;
    uint8_t *padded;

    if (!data || !*data || !size ||
        *size > UINT32_MAX - MT6589_LK_BOOTIMG_READ_SLACK)
        return -1;

    padded_size = *size + MT6589_LK_BOOTIMG_READ_SLACK;
    padded = calloc(1, padded_size);
    if (!padded)
        return -1;

    memcpy(padded, *data, *size);
    free(*data);
    *data = padded;
    *size = padded_size;
    return 0;
}

static int upload_buffer(protocol_t *proto, serial_t *s,
                         uint32_t addr, const uint8_t *data, uint32_t size,
                         const char *what) {
    const uint32_t chunk_size = 256 * 1024;

    for (uint32_t off = 0; off < size; off += chunk_size) {
        uint32_t chunk = size - off > chunk_size ? chunk_size : size - off;
        message_t msg;
        response_t resp;
        uint32_t size_be;

        message_init_write(&msg, addr + off, chunk);
        if (protocol_send_message(proto, &msg) != 0) {
            fprintf(stderr, "Failed to send %s write request at 0x%x\n",
                    what, addr + off);
            return -1;
        }

        size_be = __builtin_bswap32(chunk);
        if (serial_write(s, (uint8_t *)&size_be, sizeof(size_be)) != 0 ||
            serial_write(s, data + off, chunk) != 0) {
            fprintf(stderr, "Failed to upload %s chunk at 0x%x\n",
                    what, addr + off);
            return -1;
        }

        if (protocol_read_response(proto, &resp) != 0) {
            fprintf(stderr, "No response for %s chunk at 0x%x\n",
                    what, addr + off);
            return -1;
        }
        if (resp.type != RESP_ACK) {
            fprintf(stderr, "%s chunk at 0x%x rejected: type=0x%02x err=%u\n",
                    what, addr + off, resp.type, resp.err);
            return -1;
        }
    }

    return 0;
}

static int flush_cache_range(protocol_t *proto, uint32_t addr, uint32_t size,
                             const char *what) {
    message_t msg;
    response_t resp;

    message_init_flush_cache(&msg, addr, size);
    if (protocol_send_message(proto, &msg) != 0) {
        fprintf(stderr, "Failed to request cache flush for %s\n", what);
        return -1;
    }
    if (protocol_read_response(proto, &resp) != 0) {
        fprintf(stderr, "No response for cache flush of %s\n", what);
        return -1;
    }
    if (resp.type != RESP_ACK) {
        fprintf(stderr, "Cache flush for %s rejected: type=0x%02x err=%u\n",
                what, resp.type, resp.err);
        return -1;
    }

    return 0;
}

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

static void boot_arg_init(boot_arg_t *ba, uint32_t dram_size_per_rank,
                          uint32_t dram_ranks, uint32_t lk_mode) {
    memset(ba, 0, sizeof(*ba));
    ba->magic = BOOT_ARG_MAGIC;
    ba->boot_mode = lk_mode;
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

int run_lk_mode(serial_t *s, const soc_info_t *soc, const char *payload_path,
                const char *preloader_path, const char *lk_path,
                const upload_file_t *inputs, size_t input_count,
                const char *kernel_path, const char *ramdisk_path,
                uint32_t preloader_addr_hint, uint32_t lk_addr_hint,
                uint32_t dram_size_per_rank, uint32_t dram_ranks,
                uint32_t lk_mode) {
    printf("LK mode for %s\n", soc->name);

    if (soc->hw_code != soc_mt6589.hw_code) {
        fprintf(stderr, "LK mode currently supports MT6589 only\n");
        return -1;
    }

    if (!lk_path) {
        fprintf(stderr, "LK path required for LK mode\n");
        return -1;
    }
    if (!dram_size_per_rank || !dram_ranks || dram_ranks > 4) {
        fprintf(stderr, "DRAM size and ranks required for LK mode\n");
        return -1;
    }
    /*
     * TODO: support asymmetric DRAM ranks.  The current BOOT_ARGUMENT
     * interface stores one size per rank, but the CLI still supplies a
     * single size which is replicated to every rank.
     */
    uint64_t dram_size = (uint64_t)dram_size_per_rank * dram_ranks;
    if (dram_size > UINT32_MAX - soc->dram_base) {
        fprintf(stderr, "DRAM range overflows 32-bit address space\n");
        return -1;
    }
    if (input_count > 1) {
        fprintf(stderr, "LK mode accepts at most one input\n");
        return -1;
    }
    if (input_count && kernel_path) {
        fprintf(stderr, "Cannot combine input and kernel in LK mode\n");
        return -1;
    }

    // Preloader読み込みと解析
    uint32_t pl_size;
    uint8_t *pl_data = read_file(preloader_path, &pl_size);
    if (!pl_data) {
        fprintf(stderr, "Failed to read preloader\n");
        return -1;
    }
    uint32_t ptr_dl, ptr_ul, bldr_jump, da_addr, lk_base;
    if (analyze_preloader(pl_data, pl_size,
                          preloader_addr_hint ? preloader_addr_hint : soc->dram_base,
                          &ptr_dl, &ptr_ul, &bldr_jump, &da_addr, &lk_base) != 0) {
        fprintf(stderr, "Preloader analysis failed\n");
        free(pl_data);
        return -1;
    }
    if (lk_base == 0)
        lk_base = lk_addr_hint ? lk_addr_hint : soc->lk_base_hint;

    free(pl_data);

    // LK読み込みと解析
    uint32_t lk_size;
    uint8_t *lk_data = read_file(lk_path, &lk_size);
    if (!lk_data) {
        fprintf(stderr, "Failed to read LK\n");
        return -1;
    }
    if (lk_base == 0)
        lk_base = lk_addr_hint ? lk_addr_hint : soc->lk_base_hint;

    uint32_t lk_content_offset, lk_content_size;
    char partition_name[33];
    if (image_parse_lk(lk_data, lk_size, &lk_content_offset, &lk_content_size,
                       partition_name, sizeof(partition_name)) != 0 ||
        lk_content_offset > lk_size || lk_content_size > lk_size - lk_content_offset) {
        fprintf(stderr, "Failed to parse LK image\n");
        free(lk_data);
        return -1;
    }

    const uint8_t *lk_code = lk_data + lk_content_offset;

    uint32_t mt_part_generic_read = 0;
    uint32_t mt_part_get_partition = 0;
    if (lk_mode != LK_BOOT_FASTBOOT) {
        if (extract_mt_part_generic_read(lk_code, lk_content_size, lk_base,
                                          &mt_part_generic_read) != 0) {
            fprintf(stderr, "Failed to extract mt_part_generic_read\n");
            free(lk_data);
            return -1;
        }
        if (extract_mt_part_get_partition(lk_code, lk_content_size, lk_base,
                                           &mt_part_get_partition) != 0) {
            fprintf(stderr, "Failed to extract mt_part_get_partition\n");
            free(lk_data);
            return -1;
        }
        printf("mt_part_generic_read: 0x%x\n", mt_part_generic_read);
        printf("mt_part_get_partition: 0x%x\n", mt_part_get_partition);
    }
    printf("LK partition: %s (%u bytes)\n", partition_name, lk_content_size);

    // ペイロード読み込みと注入
    uint32_t payload_size;
    uint8_t *payload = read_file(payload_path, &payload_size);
    if (!payload) {
        fprintf(stderr, "Failed to read payload\n");
        free(lk_data);
        return -1;
    }
    payload_params_t params;
    payload_params_init(&params, soc->dram_base,
                        soc->dram_base + (uint32_t)dram_size,
                        ptr_dl, ptr_ul, SOC_MT6589);
    if (inject_params(payload, payload_size, &params) != 0) {
        fprintf(stderr, "Payload does not contain a parameter marker\n");
        free(payload);
        free(lk_data);
        return -1;
    }

    // DA送信とジャンプ
    printf("Sending payload...\n");
    if (mtk_send_da(s, da_addr, payload, payload_size) != 0) {
        fprintf(stderr, "Failed to send DA\n");
        free(payload);
        free(lk_data);
        return -1;
    }
    if (mtk_jump_da(s, da_addr) != 0) {
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
    if (protocol_send_message(&proto, &msg) != 0) {
        fprintf(stderr, "Failed to acknowledge payload handshake\n");
        free(payload);
        free(lk_data);
        return -1;
    }

    // Preloader params
    preloader_runner_params_t pl_params;
    pl_params.ptr_bldr_jump = bldr_jump;
    message_init_set_params_preloader(&msg, &pl_params);
    response_t resp;
    if (protocol_send_message(&proto, &msg) != 0 ||
        protocol_read_response(&proto, &resp) != 0 ||
        resp.type != RESP_ACK) {
        fprintf(stderr, "Failed to set preloader params\n");
        free(payload);
        free(lk_data);
        return -1;
    }

    const uint32_t boot_arg_addr = soc->boot_arg_addr;
    const uint32_t boot_arg_size = sizeof(boot_arg_t);
    const char *input_path = input_count ? inputs[0].path : NULL;

    if (lk_mode == LK_BOOT_FASTBOOT) {
        char fastboot_bootimg_path[1024];
        int fastboot_bootimg_owned = 0;
        lk_runner_params_t lk_params;

        if (lk_base != soc->lk_base_hint) {
            fprintf(stderr,
                    "LK fastboot hook requires LK at 0x%x (got 0x%x)\n",
                    soc->lk_base_hint, lk_base);
            free(payload);
            free(lk_data);
            return -1;
        }

        if (prepare_fastboot_bootimg(kernel_path, ramdisk_path, input_path,
                                     soc->dram_base, fastboot_bootimg_path,
                                     sizeof(fastboot_bootimg_path),
                                     &fastboot_bootimg_owned) != 0) {
            fprintf(stderr, "Failed to prepare fastboot boot image\n");
            free(payload);
            free(lk_data);
            return -1;
        }

        memset(&lk_params, 0, sizeof(lk_params));
        lk_params.ptr_fastboot_init =
            lk_base + MT6589_LK_FASTBOOT_INIT_OFFSET;
        lk_params.ptr_fastboot_register =
            lk_base + MT6589_LK_FASTBOOT_REGISTER_OFFSET;
        lk_params.ptr_fastboot_okay =
            lk_base + MT6589_LK_FASTBOOT_OKAY_OFFSET;
        lk_params.ptr_fastboot_fail =
            lk_base + MT6589_LK_FASTBOOT_FAIL_OFFSET;
        lk_params.ptr_udc_stop = lk_base + MT6589_LK_UDC_STOP_OFFSET;
        lk_params.ptr_mtk_wdt_init =
            lk_base + MT6589_LK_MTK_WDT_INIT_OFFSET;
        lk_params.ptr_boot_linux =
            lk_base + MT6589_LK_BOOT_LINUX_OFFSET;
        lk_params.boot_mode_addr =
            lk_base + MT6589_LK_BOOT_MODE_OFFSET;
        lk_params.machtype = MT6589_LK_MACHTYPE;

        message_init_set_params_lk(&msg, &lk_params);
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to set LK fastboot parameters\n");
            if (fastboot_bootimg_owned) unlink(fastboot_bootimg_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        /* The payload allocator owns a 1 MiB range, so reserve the fixed
         * boot argument buffer before creating the hook trampoline. */
        message_init_blacklist(&msg, boot_arg_addr,
                               boot_arg_addr + boot_arg_size);
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to reserve boot arg range\n");
            if (fastboot_bootimg_owned) unlink(fastboot_bootimg_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        message_init_hook(&msg, HOOK_FASTBOOT_INIT);
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to install fastboot_init hook\n");
            if (fastboot_bootimg_owned) unlink(fastboot_bootimg_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        boot_arg_t boot_arg;
        boot_arg_init(&boot_arg, dram_size_per_rank, dram_ranks, lk_mode);
        printf("Uploading boot arg to 0x%x...\n", boot_arg_addr);
        if (upload_buffer(&proto, s, boot_arg_addr,
                          (const uint8_t *)&boot_arg, boot_arg_size,
                          "boot argument") != 0) {
            if (fastboot_bootimg_owned) unlink(fastboot_bootimg_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        printf("Jumping to LK at 0x%x with boot arg at 0x%x\n",
               lk_base, boot_arg_addr);
        message_init_jump(&msg, lk_base, boot_arg_addr, boot_arg_size, 1, 1);
        if (protocol_send_message(&proto, &msg) != 0) {
            fprintf(stderr, "Failed to send final LK jump request\n");
            if (fastboot_bootimg_owned) unlink(fastboot_bootimg_path);
            free(payload);
            free(lk_data);
            return -1;
        }
        if (protocol_read_response(&proto, &resp) == 0 && resp.type == RESP_NACK) {
            fprintf(stderr, "LK jump rejected: err=%u\n", resp.err);
            if (fastboot_bootimg_owned) unlink(fastboot_bootimg_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        free(lk_data);
        free(payload);
        serial_close(s);

        int ret = run_host_fastboot_boot(fastboot_bootimg_path);
        if (fastboot_bootimg_owned)
            unlink(fastboot_bootimg_path);
        return ret;
    }

    // boot.img準備とアップロード
    uint32_t bootimg_addr = 0;
    uint32_t bootimg_size = 0;
    uint8_t *bootimg_data = NULL;
    uint32_t kernel_size = 0;
    uint32_t ramdisk_size = 0;
    if (kernel_path) {
        char kernel_mtk_path[] = "/tmp/da-boot-kernel-XXXXXX";
        char ramdisk_mtk_path[] = "/tmp/da-boot-rootfs-XXXXXX";
        char bootimg_path[] = "/tmp/da-boot-output-XXXXXX";
        char cmd[1024];

        if (create_temp_path(kernel_mtk_path) != 0) {
            fprintf(stderr, "Failed to create temporary KERNEL image path\n");
            free(payload);
            free(lk_data);
            return -1;
        }
        if (create_temp_path(ramdisk_mtk_path) != 0) {
            fprintf(stderr, "Failed to create temporary ROOTFS image path\n");
            unlink(kernel_mtk_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        if (wrap_file_as_mtk_image(kernel_path, kernel_mtk_path,
                                   "KERNEL", &kernel_size) != 0) {
            fprintf(stderr, "Failed to build KERNEL image\n");
            free(payload);
            free(lk_data);
            return -1;
        }

        if (ramdisk_path) {
            if (wrap_file_as_mtk_image(ramdisk_path, ramdisk_mtk_path,
                                       "ROOTFS", &ramdisk_size) != 0) {
                fprintf(stderr, "Failed to build ROOTFS image\n");
                unlink(kernel_mtk_path);
                free(payload);
                free(lk_data);
                return -1;
            }
        } else {
            uint8_t empty_rootfs[1024] = { 0 };
            if (write_mtk_image(ramdisk_mtk_path, "ROOTFS",
                                empty_rootfs, sizeof(empty_rootfs)) != 0) {
                fprintf(stderr, "Failed to build empty ROOTFS image\n");
                unlink(kernel_mtk_path);
                free(payload);
                free(lk_data);
                return -1;
            }
            ramdisk_size = sizeof(empty_rootfs);
        }

        /*
         * Keep the host-side boot.img scratch buffer away from memory that
         * the stock LK will overwrite while loading the kernel/ramdisk,
         * the LK image itself, and the preloader's fixed boot-arg buffer.
         *
         * The payload allocator scans from 0x80000000, so without these
         * reservations the large boot.img is placed directly over the LK
         * kernel destination (and, before that, over 0x800a0000).
         */
        message_init_blacklist(&msg, MT6589_LK_KERNEL_ADDR,
                               MT6589_LK_KERNEL_ADDR + MTK_BOOT_PAGE_ALIGN(kernel_size));
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to reserve LK kernel range\n");
            unlink(kernel_mtk_path);
            unlink(ramdisk_mtk_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        message_init_blacklist(&msg, MT6589_LK_RAMDISK_ADDR,
                               MT6589_LK_RAMDISK_ADDR + MTK_BOOT_PAGE_ALIGN(ramdisk_size));
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to reserve LK ramdisk range\n");
            unlink(kernel_mtk_path);
            unlink(ramdisk_mtk_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        message_init_blacklist(&msg, lk_base,
                               lk_base + lk_content_size);
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to reserve LK range\n");
            unlink(kernel_mtk_path);
            unlink(ramdisk_mtk_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        message_init_blacklist(&msg, boot_arg_addr,
                               boot_arg_addr + boot_arg_size);
        if (protocol_send_message(&proto, &msg) != 0 ||
            protocol_read_response(&proto, &resp) != 0 ||
            resp.type != RESP_ACK) {
            fprintf(stderr, "Failed to reserve boot arg range\n");
            unlink(kernel_mtk_path);
            unlink(ramdisk_mtk_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        if (create_temp_path(bootimg_path) != 0) {
            fprintf(stderr, "Failed to create temporary boot.img path\n");
            unlink(kernel_mtk_path);
            unlink(ramdisk_mtk_path);
            free(payload);
            free(lk_data);
            return -1;
        }

        snprintf(cmd, sizeof(cmd),
                 "mkbootimg --kernel %s --ramdisk %s --base 0x%x --kernel_offset 0x8000 "
                 "--ramdisk_offset 0x4000000 -o %s",
                 kernel_mtk_path, ramdisk_mtk_path, soc->dram_base,
                 bootimg_path);
        printf("Running: %s\n", cmd);
        if (system(cmd) != 0) {
            fprintf(stderr, "mkbootimg failed\n");
            unlink(kernel_mtk_path);
            unlink(ramdisk_mtk_path);
            unlink(bootimg_path);
            free(payload);
            free(lk_data);
            return -1;
        }
        unlink(kernel_mtk_path);
        unlink(ramdisk_mtk_path);

        bootimg_data = read_file(bootimg_path, &bootimg_size);
        unlink(bootimg_path);
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

    if (pad_lk_bootimg_read_window(&bootimg_data, &bootimg_size) != 0) {
        fprintf(stderr, "Failed to prepare MT6589 LK boot image read window\n");
        free(bootimg_data);
        free(payload);
        free(lk_data);
        return -1;
    }

    // 空きメモリ取得
    message_init_get_free_range(&msg, bootimg_size);
    if (protocol_send_message(&proto, &msg) != 0 ||
        protocol_read_response(&proto, &resp) != 0 ||
        resp.type != RESP_RANGE || resp.addr == 0) {
        fprintf(stderr, "Failed to get free range\n");
        free(bootimg_data);
        free(payload);
        free(lk_data);
        return -1;
    }
    bootimg_addr = resp.addr;
    printf("boot.img at 0x%x (%u bytes)\n", bootimg_addr, bootimg_size);

    // アップロード
    if (upload_buffer(&proto, s, bootimg_addr, bootimg_data, bootimg_size,
                      "boot.img") != 0) {
        free(bootimg_data);
        free(payload);
        free(lk_data);
        return -1;
    }
    free(bootimg_data);

    // ブラックリスト
    message_init_blacklist(&msg, bootimg_addr, bootimg_addr + bootimg_size);
    if (protocol_send_message(&proto, &msg) != 0 ||
        protocol_read_response(&proto, &resp) != 0 ||
        resp.type != RESP_ACK) {
        fprintf(stderr, "Failed to blacklist boot.img range\n");
        free(payload);
        free(lk_data);
        return -1;
    }

    // LKパラメータ設定
    lk_runner_params_t lk_params;
    memset(&lk_params, 0, sizeof(lk_params));
    lk_params.ptr_mt_part_generic_read = mt_part_generic_read | 1; // Thumb
    lk_params.ptr_mt_part_get_partition = mt_part_get_partition | 1;
    lk_params.bootimg_scratch_addr = bootimg_addr;
    lk_params.bootimg_scratch_size = bootimg_size;
    message_init_set_params_lk(&msg, &lk_params);
    if (protocol_send_message(&proto, &msg) != 0 ||
        protocol_read_response(&proto, &resp) != 0 ||
        resp.type != RESP_ACK) {
        fprintf(stderr, "Failed to set LK runner parameters\n");
        free(payload);
        free(lk_data);
        return -1;
    }

    // LKアップロード
    printf("Uploading LK to 0x%x...\n", lk_base);
    if (upload_buffer(&proto, s, lk_base, lk_code, lk_content_size, "LK") != 0) {
        free(payload);
        free(lk_data);
        return -1;
    }

    /* The payload will inspect and patch the freshly uploaded LK. */
    if (flush_cache_range(&proto, lk_base, lk_content_size, "LK") != 0) {
        free(payload);
        free(lk_data);
        return -1;
    }
    free(lk_data);

    // フック設定
    message_init_hook(&msg, HOOK_MT_PART_GENERIC_READ);
    if (protocol_send_message(&proto, &msg) != 0) {
        fprintf(stderr, "Failed to send mt_part_generic_read hook request\n");
        free(payload);
        return -1;
    }
    if (protocol_read_response(&proto, &resp) != 0) {
        fprintf(stderr, "No valid response from payload after mt_part_generic_read hook request\n");
        free(payload);
        return -1;
    }
    if (resp.type != RESP_ACK) {
        fprintf(stderr, "mt_part_generic_read hook rejected: type=0x%02x err=%u\n",
                resp.type, resp.err);
        fprintf(stderr, "Failed to install mt_part_generic_read hook\n");
        free(payload);
        return -1;
    }

    // Boot arg準備とアップロード
    boot_arg_t boot_arg;
    boot_arg_init(&boot_arg, dram_size_per_rank, dram_ranks, lk_mode);
    printf("Uploading boot arg to 0x%x...\n", boot_arg_addr);
    if (upload_buffer(&proto, s, boot_arg_addr,
                      (const uint8_t *)&boot_arg, boot_arg_size,
                      "boot argument") != 0) {
        free(payload);
        return -1;
    }

    // LKへジャンプ
    printf("Jumping to LK at 0x%x with boot arg at 0x%x\n",
           lk_base, boot_arg_addr);
    message_init_jump(&msg, lk_base, boot_arg_addr, boot_arg_size, 1, 1);
    if (protocol_send_message(&proto, &msg) != 0) {
        fprintf(stderr, "Failed to send final LK jump request\n");
        free(payload);
        return -1;
    }
    if (protocol_read_response(&proto, &resp) == 0 && resp.type == RESP_NACK) {
        fprintf(stderr, "LK jump rejected: err=%u\n", resp.err);
        free(payload);
        return -1;
    }

    free(payload);
    return 0;
}
