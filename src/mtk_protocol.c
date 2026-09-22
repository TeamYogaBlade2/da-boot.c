#include "mtk_protocol.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int put_byte(serial_t *s, uint8_t b) {
    return serial_write(s, &b, 1);
}

static int get_byte(serial_t *s, uint8_t *b) {
    return serial_read(s, b, 1, 2000);
}

static int get_word(serial_t *s, uint16_t *w) {
    uint8_t buf[2];
    if (serial_read(s, buf, 2, 2000) != 0) return -1;
    *w = (buf[0] << 8) | buf[1];
    return 0;
}

static int put_dword(serial_t *s, uint32_t d) {
    uint8_t buf[4] = {(d >> 24) & 0xff, (d >> 16) & 0xff, (d >> 8) & 0xff, d & 0xff};
    return serial_write(s, buf, 4);
}

static int get_dword(serial_t *s, uint32_t *d) {
    uint8_t buf[4];
    if (serial_read(s, buf, 4, 2000) != 0) return -1;
    *d = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    return 0;
}

int mtk_handshake(serial_t *s) {
    const uint8_t seq[] = {0xa0, 0x0a, 0x50, 0x05};
    uint8_t response;
    for (int i = 0; i < 4; i++) {
        // 送信
        put_byte(s, seq[i]);
        // 受信（エコー）
        if (get_byte(s, &response) != 0) return -1;
        if (response != (uint8_t)~seq[i]) {
            // リトライ
            i = -1;
            continue;
        }
    }
    // ガーベージクリア
    usleep(200000);
    serial_flush(s);
    return 0;
}

int mtk_get_hw_code(serial_t *s, uint16_t *hw_code) {
    put_byte(s, CMD_GET_HW_CODE);
    uint8_t echo;
    if (get_byte(s, &echo) != 0) return -1;
    if (echo != CMD_GET_HW_CODE) return -1;

    uint16_t status;
    if (get_word(s, hw_code) != 0) return -1;
    if (get_word(s, &status) != 0) return -1;
    return status == 0 ? 0 : -1;
}

int mtk_send_da(serial_t *s, uint32_t addr, const uint8_t *data, uint32_t len) {
    put_byte(s, CMD_SEND_DA);
    uint8_t echo;
    get_byte(s, &echo);
    if (echo != CMD_SEND_DA) return -1;

    // addr
    put_dword(s, addr);
    uint32_t echo_addr;
    get_dword(s, &echo_addr);
    if (echo_addr != addr) return -1;

    // len
    put_dword(s, len);
    uint32_t echo_len;
    get_dword(s, &echo_len);
    if (echo_len != len) return -1;

    // sig_len (0)
    put_dword(s, 0);
    uint32_t echo_sig;
    get_dword(s, &echo_sig);
    if (echo_sig != 0) return -1;

    // status 1
    uint16_t status1;
    if (get_word(s, &status1) != 0) return -1;
    if (status1 != 0) return -1;

    // データ送信（エコーなし）
    serial_write(s, data, len);

    // チェックサム受信
    uint16_t checksum;
    if (get_word(s, &checksum) != 0) return -1;

    // status 2
    uint16_t status2;
    if (get_word(s, &status2) != 0) return -1;
    return status2 == 0 ? 0 : -1;
}

int mtk_jump_da(serial_t *s, uint32_t addr) {
    put_byte(s, CMD_JUMP_DA);
    uint8_t echo;
    get_byte(s, &echo);
    if (echo != CMD_JUMP_DA) return -1;

    put_dword(s, addr);
    uint32_t echo_addr;
    get_dword(s, &echo_addr);
    if (echo_addr != addr) return -1;

    uint16_t status;
    get_word(s, &status);
    return status == 0 ? 0 : -1;
}

int mtk_read32(serial_t *s, uint32_t addr, uint32_t *data, uint32_t count) {
    put_byte(s, CMD_READ32);
    uint8_t echo;
    get_byte(s, &echo);
    if (echo != CMD_READ32) return -1;

    put_dword(s, addr);
    uint32_t echo_addr;
    get_dword(s, &echo_addr);
    if (echo_addr != addr) return -1;

    put_dword(s, count);
    uint32_t echo_count;
    get_dword(s, &echo_count);
    if (echo_count != count) return -1;

    uint16_t status;
    get_word(s, &status);
    if (status != 0) return -1;

    for (uint32_t i = 0; i < count; i++) {
        get_dword(s, &data[i]);
    }

    uint16_t final_status;
    get_word(s, &final_status);
    return final_status == 0 ? 0 : -1;
}

int mtk_write32(serial_t *s, uint32_t addr, uint32_t data) {
    put_byte(s, CMD_WRITE32);
    uint8_t echo;
    get_byte(s, &echo);
    if (echo != CMD_WRITE32) return -1;

    put_dword(s, addr);
    uint32_t echo_addr;
    get_dword(s, &echo_addr);
    if (echo_addr != addr) return -1;

    put_dword(s, data);
    uint32_t echo_data;
    get_dword(s, &echo_data);
    if (echo_data != data) return -1;

    uint16_t status;
    get_word(s, &status);
    return status == 0 ? 0 : -1;
}
