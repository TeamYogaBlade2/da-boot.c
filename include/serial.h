#ifndef SERIAL_H
#define SERIAL_H

#include <stdint.h>
#include <termios.h>

typedef struct {
    int fd;
} serial_t;

/**
 * シリアルポートを開く
 * @param port    デバイスパス (例: /dev/ttyACM0)
 * @param baudrate ボーレート (B921600 など termios の定数)
 * @return 成功時 0 以上、失敗時 -1
 */
int serial_open(const char *port, int baudrate);

/**
 * シリアルポートを閉じる
 */
void serial_close(serial_t *s);

/**
 * データを送信
 * @return 成功時 0、失敗時 -1
 */
int serial_write(serial_t *s, const uint8_t *data, uint32_t len);

/**
 * データを受信（指定バイト数に達するかタイムアウトまで）
 * @param timeout_ms タイムアウト (ミリ秒)
 * @return 成功時 0、失敗時 -1
 */
int serial_read(serial_t *s, uint8_t *data, uint32_t len, uint32_t timeout_ms);

/**
 * バッファをフラッシュ
 * @return 成功時 0、失敗時 -1
 */
int serial_flush(serial_t *s);

#endif // SERIAL_H
