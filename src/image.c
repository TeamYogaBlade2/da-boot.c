#include "image.h"
#include <string.h>
#include <stdio.h>

#define GFH_FILE_INFO_MAGIC  0x464C4945  // "FILE"
#define GFH_ROM_INFO_MAGIC   0x4D4F5220  // "ROM "
#define GFH_BL_INFO_MAGIC    0x424C2121  // "BL!!"
#define MTK_LK_PARTITION_HEADER_SIZE 0x200u

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
    typedef struct {
        char identifier[12];
        uint32_t version;
        uint32_t dev_rw_unit;
    } emmc_header_t;

    typedef struct {
        uint32_t bl_exist_magic;
        uint8_t  bl_dev;
        uint16_t bl_type;
        uint32_t bl_begin_dev_addr;
        uint32_t bl_boundary_dev_addr;
        uint32_t bl_attribute;
    } bl_descriptor_t;

    typedef struct {
        char identifier[8];
        uint32_t version;
        uint32_t boot_region_dev_addr;
        uint32_t main_region_dev_addr;
        bl_descriptor_t bl_desc;
    } brlyt_t;

    typedef struct {
        uint32_t magic_ver;
        uint16_t size;
        uint16_t type;
        char identifier[12];
        uint32_t file_ver;
        uint16_t file_type;
        uint8_t flash_dev;
        uint8_t sig_type;
        uint32_t load_addr;
        uint32_t file_len;
        uint32_t max_size;
        uint32_t content_offset;
        uint32_t sig_len;
        uint32_t jump_offset;
        uint32_t attr;
    } gfh_file_info_v1_t;

    uint32_t gfh_offset = 0;
    int has_gfh = 0;
    const gfh_file_info_v1_t *gfh;
    uint64_t file_end;
    uint64_t content_start;
    uint64_t content_end;

    if (!data || !load_addr || !jump_offset ||
        !content_offset || !content_size)
        return -1;

    /* EMMC_BOOT contains a BRLYT which locates the actual GFH. */
    if (size >= sizeof(emmc_header_t)) {
        const emmc_header_t *ehdr = (const emmc_header_t *)data;
        if (memcmp(ehdr->identifier, "EMMC_BOOT", 9) == 0 &&
            ehdr->version == 1) {
            const brlyt_t *brlyt;
            uint64_t brlyt_offset = ehdr->dev_rw_unit;
            uint64_t brlyt_end = brlyt_offset + sizeof(*brlyt);

            if (brlyt_end > size) {
                fprintf(stderr,
                        "[image] EMMC_BOOT: BRLYT out of range: offset=0x%llx size=0x%x\n",
                        (unsigned long long)brlyt_offset, size);
                return -1;
            }

            brlyt = (const brlyt_t *)(data + brlyt_offset);
            if (memcmp(brlyt->identifier, "BRLYT", 5) != 0 ||
                brlyt->version != 1) {
                fprintf(stderr,
                        "[image] EMMC_BOOT: invalid BRLYT at 0x%llx"
                        " (id=%.8s version=%u)\n",
                        (unsigned long long)brlyt_offset,
                        brlyt->identifier, brlyt->version);
                return -1;
            }

            if (brlyt->bl_desc.bl_begin_dev_addr > size ||
                brlyt->bl_desc.bl_boundary_dev_addr > size ||
                brlyt->bl_desc.bl_begin_dev_addr >
                    brlyt->bl_desc.bl_boundary_dev_addr) {
                fprintf(stderr,
                        "[image] EMMC_BOOT: invalid BL range: begin=0x%x boundary=0x%x file=0x%x\n",
                        brlyt->bl_desc.bl_begin_dev_addr,
                        brlyt->bl_desc.bl_boundary_dev_addr,
                        size);
                return -1;
            }

            gfh_offset = brlyt->bl_desc.bl_begin_dev_addr;
            has_gfh = 1;
        }
    }

    /* Bare GFH images start directly with GFH_FILE_INFO. */
    if (gfh_offset == 0 && size >= sizeof(gfh_file_info_v1_t)) {
        const gfh_file_info_v1_t *candidate =
            (const gfh_file_info_v1_t *)data;
        if ((candidate->magic_ver & 0x00FFFFFFu) == 0x004D4D4Du &&
            candidate->type == 0 &&
            memcmp(candidate->identifier, "FILE_INFO", 9) == 0)
            has_gfh = 1;
    }

    if (!has_gfh) {
        /* Raw binaries have no image metadata. */
        *load_addr = 0;
        *jump_offset = 0;
        *content_offset = 0;
        *content_size = size;
        return 0;
    }

    /* Validate the container-derived GFH location. */
    if (gfh_offset != 0) {
        if (gfh_offset > size || size - gfh_offset < sizeof(*gfh)) {
            fprintf(stderr,
                    "[image] GFH_FILE_INFO out of range: offset=0x%x size=0x%x\n",
                    gfh_offset, size);
            return -1;
        }
    }

    gfh = (const gfh_file_info_v1_t *)(data + gfh_offset);
    if ((gfh->magic_ver & 0x00FFFFFFu) != 0x004D4D4Du ||
        gfh->type != 0 ||
        memcmp(gfh->identifier, "FILE_INFO", 9) != 0 ||
        gfh->size < sizeof(*gfh) ||
        gfh->size > size - gfh_offset) {
        fprintf(stderr,
                "[image] invalid GFH_FILE_INFO at 0x%x:"
                " magic=0x%08x size=0x%x type=%u id=%.12s file_size=0x%x\n",
                gfh_offset, gfh->magic_ver, gfh->size, gfh->type,
                gfh->identifier, gfh->file_len);
        return -1;
    }

    if (gfh->file_len < gfh->jump_offset ||
        gfh->file_len - gfh->jump_offset < gfh->sig_len) {
        fprintf(stderr,
                "[image] invalid GFH_FILE_INFO sizes:"
                " file_len=0x%x jump_offset=0x%x sig_len=0x%x\n",
                gfh->file_len, gfh->jump_offset, gfh->sig_len);
        return -1;
    }

    file_end = (uint64_t)gfh_offset + gfh->file_len;
    content_start = (uint64_t)gfh_offset + gfh->jump_offset;
    content_end = file_end - gfh->sig_len;
    if (file_end > size || content_start > content_end || content_end > size)
        return -1;

    *load_addr = gfh->load_addr;
    *jump_offset = gfh->jump_offset;
    *content_offset = (uint32_t)content_start;
    *content_size = (uint32_t)(content_end - content_start);
    return 0;
}

int image_parse_lk(const uint8_t *data, uint32_t size,
                   uint32_t *content_offset, uint32_t *content_size,
                   char *partition_name, uint32_t name_len) {
    // MTKイメージは複数のパーティションを含む
    // 最初のパーティションを抽出
    // イメージヘッダ
    typedef struct __attribute__((packed)) {
        uint32_t magic;
        uint32_t size;
        char name[32];
    } img_header_t;

    if (size < sizeof(img_header_t))
        return -1;

    const img_header_t *hdr = (const img_header_t *)data;
    if (hdr->magic != 0x58881688) { // MTKイメージマジック
        // 生バイナリとして扱う
        *content_offset = 0;
        *content_size = size;
        if (partition_name) snprintf(partition_name, name_len, "RAW");
        return 0;
    }

    if (size < MTK_LK_PARTITION_HEADER_SIZE ||
        hdr->size > size - MTK_LK_PARTITION_HEADER_SIZE) {
        fprintf(stderr,
                "[image] LK partition out of range:"
                " header_size=0x%x content_size=0x%x file_size=0x%x\n",
                MTK_LK_PARTITION_HEADER_SIZE, hdr->size, size);
        return -1;
    }

    // 最初のパーティション
    if (partition_name) snprintf(partition_name, name_len, "%s", hdr->name);
    *content_offset = MTK_LK_PARTITION_HEADER_SIZE;
    *content_size = hdr->size;
    return 0;
}
