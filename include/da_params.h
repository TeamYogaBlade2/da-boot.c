#ifndef DA_PARAMS_H
#define DA_PARAMS_H

#include <stdint.h>

#define MAGIC_DA          0xDAB001
#define CURRENT_VERSION   1

typedef enum {
    SOC_MT6572 = 0,
    SOC_MT6582,
    SOC_MT6595,
    SOC_MT6589,
    SOC_UNKNOWN
} soc_type_t;

typedef struct {
    uint32_t start;
    uint32_t end;
} mem_range_t;

typedef enum {
    BLACKLIST_NONE = 0,
    BLACKLIST_RELOC,
    BLACKLIST_DL
} blacklist_mode_t;

typedef struct {
    mem_range_t range;
    blacklist_mode_t mode;
} blacklist_range_t;

#define MAX_BLACKLIST 12

typedef struct {
    uint32_t magic;
    uint32_t version;
    mem_range_t memory;
    blacklist_range_t blacklist[MAX_BLACKLIST];
    uint32_t ptr_dl;
    uint32_t ptr_ul;
    uint32_t soc;  // soc_type_t
} payload_params_t;

// 初期化関数
void payload_params_init(payload_params_t *p, uint32_t mem_start, uint32_t mem_end,
                         uint32_t dl, uint32_t ul, soc_type_t soc);

// 空きメモリ範囲の検索
int find_unused_range(const payload_params_t *p, uint32_t size, mem_range_t *out);

// ブラックリスト登録
int blacklist_dl(payload_params_t *p, uint32_t start, uint32_t end);
int blacklist_reloc(payload_params_t *p, uint32_t start, uint32_t end);

// Preloader/LKパラメータ
typedef struct {
    uint32_t ptr_bldr_jump;
} preloader_runner_params_t;

typedef struct {
    uint32_t ptr_mt_part_generic_read;
    uint32_t ptr_mt_part_get_partition;
    uint32_t bootimg_scratch_addr;
    uint32_t bootimg_scratch_size;
} lk_runner_params_t;

void payload_params_init(payload_params_t *p, uint32_t mem_start, uint32_t mem_end,
                         uint32_t dl, uint32_t ul, soc_type_t soc);
int find_unused_range(const payload_params_t *p, uint32_t size, mem_range_t *out);
int blacklist_dl(payload_params_t *p, uint32_t start, uint32_t end);
int blacklist_reloc(payload_params_t *p, uint32_t start, uint32_t end);

#endif // DA_PARAMS_H
