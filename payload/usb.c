#include "usb.h"
#include <stdint.h>
#include <stddef.h>

// グローバル関数ポインタ
static int (*g_usb_send)(const uint8_t *buf, uint32_t len) = NULL;
static int (*g_usb_recv)(uint8_t *buf, uint32_t len, uint32_t timeout) = NULL;

void usb_init(uint32_t send_fn, uint32_t recv_fn) {
    g_usb_send = (int (*)(const uint8_t*, uint32_t))send_fn;
    g_usb_recv = (int (*)(uint8_t*, uint32_t, uint32_t))recv_fn;
}

int usb_send(const uint8_t *buf, uint32_t len) {
    if (!g_usb_send) return -1;
    return g_usb_send(buf, len);
}

int usb_recv(uint8_t *buf, uint32_t len, uint32_t timeout) {
    if (!g_usb_recv) return -1;
    return g_usb_recv(buf, len, timeout);
}

// エンディアン変換付き送受信
int usb_send_word(uint16_t w) {
    uint8_t buf[2] = {(w >> 8) & 0xff, w & 0xff};
    return usb_send(buf, 2);
}

int usb_recv_word(uint16_t *w) {
    uint8_t buf[2];
    if (usb_recv(buf, 2, 0) != 0) return -1;
    *w = (buf[0] << 8) | buf[1];
    return 0;
}

int usb_send_dword(uint32_t d) {
    uint8_t buf[4] = {(d >> 24) & 0xff, (d >> 16) & 0xff, (d >> 8) & 0xff, d & 0xff};
    return usb_send(buf, 4);
}

int usb_recv_dword(uint32_t *d) {
    uint8_t buf[4];
    if (usb_recv(buf, 4, 0) != 0) return -1;
    *d = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    return 0;
}
