#ifndef USB_H
#define USB_H

#include <stdint.h>

void usb_init(uint32_t send_fn, uint32_t recv_fn);
int usb_send(const uint8_t *buf, uint32_t len);
int usb_recv(uint8_t *buf, uint32_t len, uint32_t timeout);
int usb_send_word(uint16_t w);
int usb_recv_word(uint16_t *w);
int usb_send_dword(uint32_t d);
int usb_recv_dword(uint32_t *d);

#endif // USB_H
