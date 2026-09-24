#include "mtk_protocol.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MTK_HANDSHAKE_MAX_RETRIES 16u

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
    unsigned retries = 0;
    for (size_t i = 0; i < sizeof(seq); ) {
        // 送信
        if (put_byte(s, seq[i]) != 0)
            return -1;
        // 受信（エコー）
        if (get_byte(s, &response) != 0) return -1;
        if (response != (uint8_t)~seq[i]) {
            // リトライ
            if (++retries >= MTK_HANDSHAKE_MAX_RETRIES) {
                fprintf(stderr,
                        "[mtk] handshake retry limit exceeded\n");
                return -1;
            }
            i = 0;
            continue;
        }
        i++;
    }
    // ガーベージクリア
    usleep(200000);
    serial_flush(s);
    return 0;
}

int mtk_get_hw_code(serial_t *s, uint16_t *hw_code) {
    if (put_byte(s, CMD_GET_HW_CODE) != 0) return -1;
    uint8_t echo;
    if (get_byte(s, &echo) != 0) return -1;
    if (echo != CMD_GET_HW_CODE) return -1;

    uint16_t status;
    if (get_word(s, hw_code) != 0) return -1;
    if (get_word(s, &status) != 0) return -1;
    return status == 0 ? 0 : -1;
}

int mtk_send_da(serial_t *s, uint32_t addr, const uint8_t *data, uint32_t len) {
    if (put_byte(s, CMD_SEND_DA) != 0) return -1;

    uint8_t echo;
    if (get_byte(s, &echo) != 0) return -1;
    if (echo != CMD_SEND_DA) {
        fprintf(stderr, "[mtk] SEND_DA command echo mismatch: 0x%02x\n", echo);
        return -1;
    }

    // addr
    if (put_dword(s, addr) != 0) return -1;
    uint32_t echo_addr;
    if (get_dword(s, &echo_addr) != 0) return -1;
    if (echo_addr != addr) {
        fprintf(stderr,
                "[mtk] SEND_DA address echo mismatch: got 0x%08x expected 0x%08x\n",
                echo_addr, addr);
        return -1;
    }

    // len
    if (put_dword(s, len) != 0) return -1;
    uint32_t echo_len;
    if (get_dword(s, &echo_len) != 0) return -1;
    if (echo_len != len) {
        fprintf(stderr,
                "[mtk] SEND_DA length echo mismatch: got 0x%x expected 0x%x\n",
                echo_len, len);
        return -1;
    }

    // sig_len (0)
    if (put_dword(s, 0) != 0) return -1;
    uint32_t echo_sig;
    if (get_dword(s, &echo_sig) != 0) return -1;
    if (echo_sig != 0) {
        fprintf(stderr, "[mtk] SEND_DA signature length echo: 0x%x\n", echo_sig);
        return -1;
    }

    // status 1
    uint16_t status1;
    if (get_word(s, &status1) != 0) return -1;
    if (status1 != 0) {
        fprintf(stderr, "[mtk] SEND_DA range status: 0x%04x\n", status1);
        return -1;
    }

    // データ送信（エコーなし）
    if (serial_write(s, data, len) != 0) return -1;

    // チェックサム受信
    uint16_t checksum;
    if (get_word(s, &checksum) != 0) return -1;

    // status 2
    uint16_t status2;
    if (get_word(s, &status2) != 0) return -1;
    if (status2 != 0) {
        fprintf(stderr,
                "[mtk] SEND_DA verify status: 0x%04x (checksum=0x%04x)\n",
                status2, checksum);
        return -1;
    }
    return 0;
}

int mtk_jump_da(serial_t *s, uint32_t addr) {
    if (put_byte(s, CMD_JUMP_DA) != 0) return -1;
    uint8_t echo;
    if (get_byte(s, &echo) != 0) return -1;
    if (echo != CMD_JUMP_DA) return -1;

    if (put_dword(s, addr) != 0) return -1;
    uint32_t echo_addr;
    if (get_dword(s, &echo_addr) != 0) return -1;
    if (echo_addr != addr) return -1;

    uint16_t status;
    if (get_word(s, &status) != 0) return -1;
    return status == 0 ? 0 : -1;
}

int mtk_read32(serial_t *s, uint32_t addr, uint32_t *data, uint32_t count) {
    if (count && !data) return -1;
    if (put_byte(s, CMD_READ32) != 0) return -1;
    uint8_t echo;
    if (get_byte(s, &echo) != 0) return -1;
    if (echo != CMD_READ32) return -1;

    if (put_dword(s, addr) != 0) return -1;
    uint32_t echo_addr;
    if (get_dword(s, &echo_addr) != 0) return -1;
    if (echo_addr != addr) return -1;

    if (put_dword(s, count) != 0) return -1;
    uint32_t echo_count;
    if (get_dword(s, &echo_count) != 0) return -1;
    if (echo_count != count) return -1;

    uint16_t status;
    if (get_word(s, &status) != 0) return -1;
    if (status != 0) return -1;

    for (uint32_t i = 0; i < count; i++) {
        if (get_dword(s, &data[i]) != 0) return -1;
    }

    uint16_t final_status;
    if (get_word(s, &final_status) != 0) return -1;
    return final_status == 0 ? 0 : -1;
}

int mtk_write32(serial_t *s, uint32_t addr, uint32_t data) {
    if (put_byte(s, CMD_WRITE32) != 0) return -1;
    uint8_t echo;
    if (get_byte(s, &echo) != 0) return -1;
    if (echo != CMD_WRITE32) return -1;

    if (put_dword(s, addr) != 0) return -1;
    uint32_t echo_addr;
    if (get_dword(s, &echo_addr) != 0) return -1;
    if (echo_addr != addr) return -1;

    if (put_dword(s, data) != 0) return -1;
    uint32_t echo_data;
    if (get_dword(s, &echo_data) != 0) return -1;
    if (echo_data != data) return -1;

    uint16_t status;
    if (get_word(s, &status) != 0) return -1;
    return status == 0 ? 0 : -1;
}
