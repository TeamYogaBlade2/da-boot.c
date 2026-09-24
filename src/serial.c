#include "serial.h"
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

static int monotonic_ms(uint64_t *value) {
    struct timespec ts;

    if (!value || clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;

    *value = (uint64_t)ts.tv_sec * 1000u +
             (uint64_t)ts.tv_nsec / 1000000u;
    return 0;
}

int serial_open(const char *port, int baudrate) {
    int fd = open(port, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) return -1;

    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) {
        close(fd);
        return -1;
    }

    cfmakeraw(&tty);

    cfsetospeed(&tty, baudrate);
    cfsetispeed(&tty, baudrate);

    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~CRTSCTS;

    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 10; // 1秒タイムアウト

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

void serial_close(serial_t *s) {
    if (s && s->fd >= 0) close(s->fd);
    s->fd = -1;
}

int serial_write(serial_t *s, const uint8_t *data, uint32_t len) {
    uint32_t written = 0;
    while (written < len) {
        ssize_t n = write(s->fd, data + written, len - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) return -1;
        written += n;
    }
    return 0;
}

int serial_read(serial_t *s, uint8_t *data, uint32_t len, uint32_t timeout_ms) {
    uint32_t read_total = 0;
    uint64_t start_ms;

    if (monotonic_ms(&start_ms) != 0)
        return -1;

    while (read_total < len) {
        uint64_t now_ms;
        if (monotonic_ms(&now_ms) != 0 || now_ms - start_ms >= timeout_ms)
            return -1;

        ssize_t n = read(s->fd, data + read_total, len - read_total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            return -1;
        }
        if (n == 0) {
            usleep(1000);
            continue;
        }
        read_total += n;
    }
    return 0;
}

int serial_flush(serial_t *s) {
    return tcflush(s->fd, TCIOFLUSH);
}
