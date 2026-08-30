#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <libgen.h>
#include "serial.h"
#include "mtk_protocol.h"
#include "da_protocol.h"
#include "soc_db.h"
#include "patcher.h"
#include "image.h"
#include "da_params.h"

// 前方宣言
int run_preloader_mode(serial_t *s, const soc_info_t *soc, const char *payload_path,
                       const char *preloader_path, const char *lk_path,
                       const char *input_path, uint32_t input_addr,
                       const char *kernel_path, const char *ramdisk_path,
                       uint32_t dram_size_per_rank, uint32_t dram_ranks,
                       uint32_t jump_addr);

int run_lk_mode(serial_t *s, const soc_info_t *soc, const char *payload_path,
                const char *preloader_path, const char *lk_path,
                const char *input_path, uint32_t input_addr,
                const char *kernel_path, const char *ramdisk_path,
                uint32_t dram_size_per_rank, uint32_t dram_ranks);

int run_repl_mode(serial_t *s);

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
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -p, --preloader <file>    Preloader binary path (required)\n");
    printf("  -l, --lk <file>           LK binary path\n");
    printf("  -i, --input <file@addr>   Input binary to upload\n");
    printf("  -k, --kernel <file>       Kernel image\n");
    printf("  -r, --ramdisk <file>      Ramdisk image\n");
    printf("  -j, --jump <addr>         Final jump address\n");
    printf("  -d, --dram-size <size>    DRAM size per rank (hex)\n");
    printf("  -n, --dram-ranks <num>    DRAM rank count\n");
    printf("  -m, --mode <mode>         Boot mode: preloader|repl\n");
    printf("  -h, --help                Show this help\n");
}

int main(int argc, char *argv[]) {
    const char *preloader_path = NULL;
    const char *lk_path = NULL;
    const char *input_path = NULL;
    uint32_t input_addr = 0;
    const char *kernel_path = NULL;
    const char *ramdisk_path = NULL;
    uint32_t jump_addr = 0;
    uint32_t dram_size_per_rank = 0;
    uint32_t dram_ranks = 0;
    const char *mode = "preloader";
    const char *payload_path = "payload/payload.bin";

    static struct option long_opts[] = {
        {"preloader", required_argument, 0, 'p'},
        {"lk", required_argument, 0, 'l'},
        {"input", required_argument, 0, 'i'},
        {"kernel", required_argument, 0, 'k'},
        {"ramdisk", required_argument, 0, 'r'},
        {"jump", required_argument, 0, 'j'},
        {"dram-size", required_argument, 0, 'd'},
        {"dram-ranks", required_argument, 0, 'n'},
        {"mode", required_argument, 0, 'm'},
        {"payload", required_argument, 0, 'P'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:i:k:r:j:d:n:m:P:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': preloader_path = optarg; break;
            case 'l': lk_path = optarg; break;
            case 'i': {
                char *at = strrchr(optarg, '@');
                if (!at) {
                    fprintf(stderr, "Input must be file@addr\n");
                    exit(1);
                }
                *at = '\0';
                input_path = optarg;
                input_addr = strtoul(at+1, NULL, 0);
                break;
            }
            case 'k': kernel_path = optarg; break;
            case 'r': ramdisk_path = optarg; break;
            case 'j': jump_addr = strtoul(optarg, NULL, 0); break;
            case 'd': dram_size_per_rank = strtoul(optarg, NULL, 0); break;
            case 'n': dram_ranks = strtoul(optarg, NULL, 0); break;
            case 'm': mode = optarg; break;
            case 'P': payload_path = optarg; break;
            case 'h': print_usage(argv[0]); exit(0);
            default: print_usage(argv[0]); exit(1);
        }
    }

    if (!preloader_path) {
        fprintf(stderr, "Preloader path required\n");
        print_usage(argv[0]);
        exit(1);
    }

    // シリアルポート検出
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
        exit(1);
    }
    printf("SoC: %s\n", soc->name);

    if (strcmp(mode, "repl") == 0) {
        run_repl_mode(&serial);
    } else {
        // Preloaderモード（LKモードも含む）
        if (lk_path || input_path || kernel_path) {
            run_lk_mode(&serial, soc, payload_path, preloader_path, lk_path,
                        input_path, input_addr, kernel_path, ramdisk_path,
                        dram_size_per_rank, dram_ranks);
        } else {
            run_preloader_mode(&serial, soc, payload_path, preloader_path, lk_path,
                               input_path, input_addr, kernel_path, ramdisk_path,
                               dram_size_per_rank, dram_ranks, jump_addr);
        }
    }

    serial_close(&serial);
    return 0;
}
