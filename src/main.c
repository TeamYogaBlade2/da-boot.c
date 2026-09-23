#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <stdint.h>

#include "serial.h"
#include "mtk_protocol.h"
#include "soc_db.h"
#include "boot.h"

typedef enum {
    MODE_PRELOADER,
    MODE_LK,
    MODE_REPL,
} boot_mode_t;

enum {
    OPT_PRELOADER_ADDR = 1000,
    OPT_LK_ADDR,
    OPT_DTB,
};

// シリアルポート検出（MediaTek USB）
static int find_mtk_port(char *port_name, size_t len) {
    // 実装: /dev/ttyACM* または /dev/ttyUSB* を列挙
    // ここでは簡易的に最初のttyACMを返す
    DIR *dir = opendir("/dev");
    if (!dir) return -1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "ttyACM", 6) == 0 || strncmp(entry->d_name, "ttyUSB", 6) == 0) {
            snprintf(port_name, len, "/dev/%s", entry->d_name);
            closedir(dir);
            return 0;
        }
    }
    closedir(dir);
    return -1;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options] <mode>\n", prog);
    printf("\n");
    printf("Modes:\n");
    printf("  preloader                  Boot binaries after Preloader\n");
    printf("  lk                         Boot after LK\n");
    printf("  repl                       Enter payload REPL\n");
    printf("\n");
    printf("Options:\n");
    printf("  -p, --preloader <file>     Preloader binary path (required)\n");
    printf("      --preloader-addr <addr>\n");
    printf("                              Preloader base for raw binaries\n");
    printf("  -l, --lk <file>            LK binary path\n");
    printf("      --lk-addr <addr>       LK base if automatic detection fails\n");
    printf("  -m, --lk-mode <mode>       LK boot mode\n");
    printf("      --dram-size-per-rank <size>\n");
    printf("                              DRAM size per rank\n");
    printf("  -n, --dram-ranks <num>     DRAM rank count\n");
    printf("  -k, --kernel <file>        zImage path\n");
    printf("  -r, --ramdisk <file>       initrd path (requires --kernel)\n");
    printf("      --dtb <file>           Device tree blob for LK mode\n");
    printf("  -i, --input <file@addr>    Binary to upload (repeatable)\n");
    printf("  -j, --jump-address <addr>  Final jump address\n");
    printf("      --payload <file>       C implementation-specific payload path\n");
    printf("  -h, --help                 Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -p preloader.bin preloader\n", prog);
    printf("  %s -p preloader.bin -i uboot.bin@0x48000000 -j 0x48000000 preloader\n", prog);
    printf("  %s -p preloader.bin -l lk.bin --kernel zImage \\\n"
           "    --dram-size-per-rank 0x20000000 --dram-ranks 2 lk\n", prog);
    printf("  %s -p preloader.bin repl\n", prog);
}

static int parse_u32(const char *text, uint32_t *value) {
    char *end;
    unsigned long long v;

    if (!text || !*text || !value)
        return -1;

    errno = 0;
    end = NULL;
    v = strtoull(text, &end, 0);
    if (errno == ERANGE || end == text || *end != '\0' || v > UINT32_MAX)
        return -1;

    *value = (uint32_t)v;
    return 0;
}

static int parse_input_spec(const char *spec, upload_file_t *out) {
    const char *at;
    char *path;
    uint32_t addr;
    size_t path_len;

    if (!spec || !out)
        return -1;

    at = strrchr(spec, '@');
    if (!at || at == spec || !at[1])
        return -1;

    if (parse_u32(at + 1, &addr) != 0)
        return -1;

    path_len = (size_t)(at - spec);
    path = malloc(path_len + 1);
    if (!path)
        return -1;

    memcpy(path, spec, path_len);
    path[path_len] = '\0';

    out->path = path;
    out->addr = addr;
    return 0;
}

static int append_input(upload_file_t **inputs, size_t *count,
                        size_t *capacity, const char *spec) {
    upload_file_t input;
    upload_file_t *new_inputs;
    size_t new_capacity;

    if (parse_input_spec(spec, &input) != 0) {
        fprintf(stderr, "Invalid input specification: %s\n", spec);
        return -1;
    }

    if (*count == *capacity) {
        new_capacity = *capacity ? *capacity * 2 : 4;
        new_inputs = realloc(*inputs, new_capacity * sizeof(**inputs));
        if (!new_inputs) {
            free((void *)input.path);
            return -1;
        }
        *inputs = new_inputs;
        *capacity = new_capacity;
    }

    (*inputs)[(*count)++] = input;
    return 0;
}

static void free_inputs(upload_file_t *inputs, size_t count) {
    size_t i;

    for (i = 0; i < count; i++)
        free((void *)inputs[i].path);
    free(inputs);
}

static int parse_lk_mode(const char *text, uint32_t *mode) {
    struct {
        const char *name;
        uint32_t value;
    } modes[] = {
        { "normal", LK_BOOT_NORMAL },
        { "meta", LK_BOOT_META },
        { "recovery", LK_BOOT_RECOVERY },
        { "sw-reboot", LK_BOOT_SW_REBOOT },
        { "factory", LK_BOOT_FACTORY },
        { "advmeta", LK_BOOT_ADVMETA },
        { "ate-factory", LK_BOOT_ATE_FACTORY },
        { "alarm", LK_BOOT_ALARM },
        { "fastboot", LK_BOOT_FASTBOOT },
        { "download", LK_BOOT_DOWNLOAD },
    };
    size_t i;

    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        if (strcmp(text, modes[i].name) == 0) {
            *mode = modes[i].value;
            return 0;
        }
    }

    return -1;
}

int main(int argc, char *argv[]) {
    const char *preloader_path = NULL;
    const char *lk_path = NULL;
    const char *kernel_path = NULL;
    const char *ramdisk_path = NULL;
    const char *dtb_path = NULL;
    upload_file_t *inputs = NULL;
    size_t input_count = 0;
    size_t input_capacity = 0;
    uint32_t preloader_addr_hint = 0;
    uint32_t lk_addr_hint = 0;
    uint32_t jump_addr = 0;
    uint32_t dram_size_per_rank = 0;
    uint32_t dram_ranks = 0;
    uint32_t lk_mode = LK_BOOT_NORMAL;
    const char *payload_path = "payload/payload.bin";
    boot_mode_t mode;
    const char *mode_name;

    static struct option long_opts[] = {
        {"preloader", required_argument, 0, 'p'},
        {"preloader-addr", required_argument, 0, OPT_PRELOADER_ADDR},
        {"lk", required_argument, 0, 'l'},
        {"lk-addr", required_argument, 0, OPT_LK_ADDR},
        {"lk-mode", required_argument, 0, 'm'},
        {"input", required_argument, 0, 'i'},
        {"kernel", required_argument, 0, 'k'},
        {"ramdisk", required_argument, 0, 'r'},
        {"dtb", required_argument, 0, OPT_DTB},
        {"jump-address", required_argument, 0, 'j'},
        {"dram-size-per-rank", required_argument, 0, 'd'},
        {"dram-ranks", required_argument, 0, 'n'},
        {"payload", required_argument, 0, 'P'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+p:l:i:k:r:j:d:n:m:P:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': preloader_path = optarg; break;
            case 'l': lk_path = optarg; break;
            case 'i':
                if (append_input(&inputs, &input_count, &input_capacity, optarg) != 0) {
                    free_inputs(inputs, input_count);
                    return 1;
                }
                break;
            case 'k': kernel_path = optarg; break;
            case 'r': ramdisk_path = optarg; break;
            case OPT_DTB: dtb_path = optarg; break;
            case 'j':
                if (parse_u32(optarg, &jump_addr) != 0) {
                    fprintf(stderr, "Invalid jump address: %s\n", optarg);
                    free_inputs(inputs, input_count);
                    return 1;
                }
                break;
            case 'd':
                if (parse_u32(optarg, &dram_size_per_rank) != 0) {
                    fprintf(stderr, "Invalid DRAM size per rank: %s\n", optarg);
                    free_inputs(inputs, input_count);
                    return 1;
                }
                break;
            case 'n':
                if (parse_u32(optarg, &dram_ranks) != 0) {
                    fprintf(stderr, "Invalid DRAM rank count: %s\n", optarg);
                    free_inputs(inputs, input_count);
                    return 1;
                }
                break;
            case 'm':
                if (parse_lk_mode(optarg, &lk_mode) != 0) {
                    fprintf(stderr, "Invalid LK mode: %s\n", optarg);
                    free_inputs(inputs, input_count);
                    return 1;
                }
                break;
            case OPT_PRELOADER_ADDR:
                if (parse_u32(optarg, &preloader_addr_hint) != 0) {
                    fprintf(stderr, "Invalid Preloader address: %s\n", optarg);
                    free_inputs(inputs, input_count);
                    return 1;
                }
                break;
            case OPT_LK_ADDR:
                if (parse_u32(optarg, &lk_addr_hint) != 0) {
                    fprintf(stderr, "Invalid LK address: %s\n", optarg);
                    free_inputs(inputs, input_count);
                    return 1;
                }
                break;
            case 'P': payload_path = optarg; break;
            case 'h':
                print_usage(argv[0]);
                free_inputs(inputs, input_count);
                return 0;
            default:
                print_usage(argv[0]);
                free_inputs(inputs, input_count);
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Boot mode is required\n");
        print_usage(argv[0]);
        free_inputs(inputs, input_count);
        return 1;
    }

    mode_name = argv[optind++];
    if (strcmp(mode_name, "preloader") == 0)
        mode = MODE_PRELOADER;
    else if (strcmp(mode_name, "lk") == 0)
        mode = MODE_LK;
    else if (strcmp(mode_name, "repl") == 0)
        mode = MODE_REPL;
    else {
        fprintf(stderr, "Unknown boot mode: %s\n", mode_name);
        print_usage(argv[0]);
        free_inputs(inputs, input_count);
        return 1;
    }

    if (optind != argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        free_inputs(inputs, input_count);
        return 1;
    }

    if (!preloader_path) {
        fprintf(stderr, "Preloader path required\n");
        print_usage(argv[0]);
        free_inputs(inputs, input_count);
        return 1;
    }

    if (ramdisk_path && !kernel_path) {
        fprintf(stderr, "--ramdisk requires --kernel\n");
        free_inputs(inputs, input_count);
        return 1;
    }

    switch (mode) {
        case MODE_PRELOADER:
            if (lk_path || kernel_path || ramdisk_path || dtb_path ||
                dram_size_per_rank || dram_ranks || lk_mode != LK_BOOT_NORMAL ||
                lk_addr_hint) {
                fprintf(stderr, "LK-specific options require the lk mode\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            if (input_count && !jump_addr) {
                fprintf(stderr, "preloader mode with --input requires --jump-address\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            break;
        case MODE_LK:
            if (!lk_path) {
                fprintf(stderr, "lk mode requires --lk\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            if (input_count > 1) {
                fprintf(stderr, "lk mode accepts at most one --input\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            if (input_count && kernel_path) {
                fprintf(stderr, "lk mode cannot combine --input and --kernel\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            if (!input_count && !kernel_path) {
                fprintf(stderr, "lk mode requires --input or --kernel\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            if (jump_addr) {
                fprintf(stderr, "lk mode cannot use --jump-address\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            if (!dram_size_per_rank || !dram_ranks || dram_ranks > 4) {
                fprintf(stderr,
                        "lk mode requires --dram-size-per-rank and --dram-ranks "
                        "(1..4)\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            break;
        case MODE_REPL:
            if (lk_path || kernel_path || ramdisk_path || input_count || dtb_path ||
                jump_addr || dram_size_per_rank || dram_ranks ||
                lk_mode != LK_BOOT_NORMAL || preloader_addr_hint || lk_addr_hint) {
                fprintf(stderr, "repl mode only accepts the preloader and payload options\n");
                free_inputs(inputs, input_count);
                return 1;
            }
            break;
    }

    char port_name[256];
    printf("Waiting for device...\n");
    while (find_mtk_port(port_name, sizeof(port_name)) != 0) {
        usleep(500000);
        printf(".");
        fflush(stdout);
    }
    printf("\nFound device at %s\n", port_name);

    // シリアルオープン
    serial_t serial;
    serial.fd = serial_open(port_name, B921600);
    if (serial.fd < 0) {
        fprintf(stderr, "Failed to open serial port\n");
        exit(1);
    }

    // ハンドシェイク
    printf("Handshaking...\n");
    if (mtk_handshake(&serial) != 0) {
        fprintf(stderr, "Handshake failed\n");
        serial_close(&serial);
        exit(1);
    }

    // HWコード取得
    uint16_t hw_code;
    if (mtk_get_hw_code(&serial, &hw_code) != 0) {
        fprintf(stderr, "Failed to get HW code\n");
        serial_close(&serial);
        exit(1);
    }
    printf("HW code: 0x%04x\n", hw_code);

    const soc_info_t *soc = soc_get_by_hw_code(hw_code);
    if (!soc) {
        fprintf(stderr, "Unsupported SoC: 0x%04x\n", hw_code);
        serial_close(&serial);
        free_inputs(inputs, input_count);
        return 1;
    }
    printf("SoC: %s\n", soc->name);

    int ret;

    switch (mode) {
        case MODE_PRELOADER:
            ret = run_preloader_mode(&serial, soc, payload_path, preloader_path,
                                     inputs, input_count,
                                     preloader_addr_hint, jump_addr);
            break;
        case MODE_LK:
            ret = run_lk_mode(&serial, soc, payload_path, preloader_path,
                              lk_path, inputs, input_count,
                              kernel_path, ramdisk_path,
                              dtb_path,
                              preloader_addr_hint, lk_addr_hint,
                              dram_size_per_rank, dram_ranks, lk_mode);
            break;
        case MODE_REPL:
            ret = run_repl_mode(&serial);
            break;
        default:
            ret = -1;
            break;
    }

    serial_close(&serial);
    free_inputs(inputs, input_count);
    return ret == 0 ? 0 : 1;
}
