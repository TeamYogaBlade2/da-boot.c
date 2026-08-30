#ifndef MTK_PROTOCOL_H
#define MTK_PROTOCOL_H

#include <stdint.h>
#include "serial.h"

// レガシーMTKコマンド
#define CMD_GET_HW_CODE    0xfd
#define CMD_SEND_DA        0xd7
#define CMD_JUMP_DA        0xd5
#define CMD_READ32         0xd1
#define CMD_WRITE32        0xd4

// ハンドシェイク
int mtk_handshake(serial_t *s);
int mtk_get_hw_code(serial_t *s, uint16_t *hw_code);
int mtk_send_da(serial_t *s, uint32_t addr, const uint8_t *data, uint32_t len);
int mtk_jump_da(serial_t *s, uint32_t addr);
int mtk_read32(serial_t *s, uint32_t addr, uint32_t *data, uint32_t count);
int mtk_write32(serial_t *s, uint32_t addr, uint32_t data);

#endif // MTK_PROTOCOL_H
