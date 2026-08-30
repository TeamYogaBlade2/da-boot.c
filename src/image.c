#include "image.h"
#include <string.h>
#include <stdio.h>

#define GFH_FILE_INFO_MAGIC  0x464C4945  // "FILE"
#define GFH_ROM_INFO_MAGIC   0x4D4F5220  // "ROM "
#define GFH_BL_INFO_MAGIC    0x424C2121  // "BL!!"

// GFHヘッダ構造
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t size;
} gfh_header_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;         // "FILE"
    uint32_t size;
    uint32_t type;
    uint32_t load_addr;
    uint32_t file_len;
    uint32_t max_size;
    uint32_t jump_offset;
    uint32_t attr;
} gfh_file_info_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;         // "ROM "
    uint32_t size;
    uint32_t type;
    uint32_t addr;
    uint32_t len;
    uint32_t attr;
} gfh_rom_info_t;

int image_parse_preloader(const uint8_t *data, uint32_t size,
                          uint32_t *load_addr, uint32_t *jump_offset,
                          uint32_t *content_offset, uint32_t *content_size) {
    // ヘッダ検出
    if (size < 0x800) return -1;

    // "EMMC_BOOT" または "MMM" チェック
    if (memcmp(data, "EMMC_BOOT", 9) == 0) {
        *content_offset = 0xB00;
    } else if (memcmp(data, "MMM", 3) == 0) {
        *content_offset = 0x300;
    } else {
        // 生バイナリ
        *content_offset = 0;
        *load_addr = 0;
        *jump_offset = 0;
        *content_size = size;
        return 0;
    }

    // GFHパース
    const uint8_t *g = data + *content_offset;
    uint32_t off = 0;
    while (off + sizeof(gfh_header_t) <= size - *content_offset) {
        gfh_header_t *hdr = (gfh_header_t*)(g + off);
        if (hdr->magic == GFH_FILE_INFO_MAGIC) {
            gfh_file_info_t *fi = (gfh_file_info_t*)(g + off);
            *load_addr = fi->load_addr;
            *jump_offset = fi->jump_offset;
            *content_size = fi->file_len;
            return 0;
        }
        off += hdr->size;
        if (hdr->size == 0) break;
    }
    return -1;
}

int image_parse_lk(const uint8_t *data, uint32_t size,
                   uint32_t *content_offset, uint32_t *content_size,
                   char *partition_name, uint32_t name_len) {
    // MTKイメージは複数のパーティションを含む
    // 最初のパーティションを抽出
    if (size < 512) return -1;

    // イメージヘッダ
    typedef struct __attribute__((packed)) {
        char name[32];
        uint32_t magic;
        uint32_t size;
    } img_header_t;

    img_header_t *hdr = (img_header_t*)data;
    if (hdr->magic != 0x58881688) { // MTKイメージマジック
        // 生バイナリとして扱う
        *content_offset = 0;
        *content_size = size;
        if (partition_name) snprintf(partition_name, name_len, "RAW");
        return 0;
    }

    // 最初のパーティション
    if (partition_name) snprintf(partition_name, name_len, "%s", hdr->name);
    *content_offset = sizeof(img_header_t);
    *content_size = hdr->size;
    return 0;
}
