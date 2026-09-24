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
    if (len <= 0 || (uint64_t)len > UINT32_MAX) {
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

// ペイロードパラメータ注入
int inject_params(uint8_t *payload, uint32_t payload_size,
                  const payload_params_t *params) {
    struct {
        uint32_t magic;
        uint32_t version;
    } marker = {
        .magic = MAGIC_DA,
        .version = CURRENT_VERSION,
    };

    if (!payload || !params || payload_size < sizeof(*params))
        return -1;

    for (uint32_t i = 0; i + sizeof(payload_params_t) <= payload_size; i++) {
        if (memcmp(payload + i, &marker, sizeof(marker)) == 0) {
            memcpy(payload + i, params, sizeof(payload_params_t));
            printf("Params injected at offset 0x%x\n", i);
            return 0;
        }
    }
    fprintf(stderr, "Warning: MAGIC not found in payload\n");
    return -1;
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
