#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "da_params.h"
#include "patcher.h"

// ファイル読み込み
uint8_t *read_file(const char *path, uint32_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = malloc(len);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *size = (uint32_t)len;
    return buf;
}

// Preloader解析
int analyze_preloader(const uint8_t *data, uint32_t size, uint32_t base,
                      uint32_t *ptr_dl, uint32_t *ptr_ul,
                      uint32_t *bldr_jump, uint32_t *da_addr,
                      uint32_t *lk_base) {
    if (extract_preloader_dl_ul(data, size, base, ptr_dl, ptr_ul) != 0) {
        fprintf(stderr, "Failed to extract DL/UL pointers\n");
        return -1;
    }
    if (extract_bldr_jump(data, size, base, bldr_jump, da_addr) != 0) {
        fprintf(stderr, "Failed to extract bldr_jump\n");
        return -1;
    }
    if (extract_lk_base(data, size, base, lk_base) != 0) {
        fprintf(stderr, "Warning: failed to extract LK base, using default\n");
        *lk_base = 0;
    }
    return 0;
}

// ペイロードパラメータ注入
void inject_params(uint8_t *payload, uint32_t payload_size,
                   const payload_params_t *params) {
    const uint32_t magic = MAGIC_DA;
    for (uint32_t i = 0; i + sizeof(payload_params_t) <= payload_size; i++) {
        if (memcmp(payload + i, &magic, 4) == 0) {
            memcpy(payload + i, params, sizeof(payload_params_t));
            printf("Params injected at offset 0x%x\n", i);
            return;
        }
    }
    fprintf(stderr, "Warning: MAGIC not found in payload\n");
}

// PayloadParams 初期化
void payload_params_init(payload_params_t *p, uint32_t mem_start, uint32_t mem_end,
                         uint32_t dl, uint32_t ul, soc_type_t soc) {
    memset(p, 0, sizeof(*p));
    p->magic = MAGIC_DA;
    p->version = CURRENT_VERSION;
    p->memory.start = mem_start;
    p->memory.end = mem_end;
    p->ptr_dl = dl;
    p->ptr_ul = ul;
    p->soc = soc;
    for (int i = 0; i < MAX_BLACKLIST; i++) {
        p->blacklist[i].mode = BLACKLIST_NONE;
    }
}
