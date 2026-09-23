#include "da_protocol.h"
#include <string.h>
#include <stdio.h>

// 簡易シリアライズ（固定長構造体として）
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t data[255];
} wire_msg_t;

void protocol_init(protocol_t *p, serial_t *io) {
	memset(p, 0, sizeof(*p));
    p->io = io;
}

static void protocol_flush_payload_log(protocol_t *p) {
	if (!p->payload_log_len) return;
	fputs("[payload] ", stdout);
	fwrite(p->payload_log_line, 1, p->payload_log_len, stdout);
	fputc('\n', stdout);
	fflush(stdout);
	p->payload_log_len = 0;
}

static void protocol_append_payload_log(protocol_t *p,
						const uint8_t *data, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		uint8_t ch = data[i];

		if (ch == '\r') continue;
		if (ch == '\n') {
			protocol_flush_payload_log(p);
			continue;
		}

		if (p->payload_log_len == sizeof(p->payload_log_line))
			protocol_flush_payload_log(p);
		p->payload_log_line[p->payload_log_len++] = ch;
	}
}

int protocol_send_message(protocol_t *p, const message_t *msg) {
    uint8_t buf[512];
    uint32_t len = 0;

    buf[len++] = msg->type;

    switch (msg->type) {
        case MSG_ACK:
            break;
        case MSG_READ:
            memcpy(&buf[len], &msg->read.addr, 4); len += 4;
            memcpy(&buf[len], &msg->read.size, 4); len += 4;
            break;
        case MSG_WRITE:
            memcpy(&buf[len], &msg->write.addr, 4); len += 4;
            memcpy(&buf[len], &msg->write.size, 4); len += 4;
            break;
        case MSG_FLUSH_CACHE:
            memcpy(&buf[len], &msg->flush_cache.addr, 4); len += 4;
            memcpy(&buf[len], &msg->flush_cache.size, 4); len += 4;
            break;
        case MSG_JUMP:
            memcpy(&buf[len], &msg->jump.addr, 4); len += 4;
            memcpy(&buf[len], &msg->jump.r0, 4); len += 4;
            memcpy(&buf[len], &msg->jump.r1, 4); len += 4;
            buf[len++] = msg->jump.has_r0 ? 1 : 0;
            buf[len++] = msg->jump.has_r1 ? 1 : 0;
            break;
        case MSG_HOOK:
            buf[len++] = msg->hook;
            break;
        case MSG_GET_FREE_RANGE:
            memcpy(&buf[len], &msg->get_free_range.size, 4); len += 4;
            memcpy(&buf[len], &msg->get_free_range.min_addr, 4); len += 4;
            break;
        case MSG_BLACKLIST_RANGE:
            memcpy(&buf[len], &msg->blacklist.start, 4); len += 4;
            memcpy(&buf[len], &msg->blacklist.end, 4); len += 4;
            break;
        case MSG_SET_PARAMS:
            buf[len++] = msg->set_params.type;
            if (msg->set_params.type == PARAMS_PRELOADER) {
                memcpy(&buf[len], &msg->set_params.preloader.ptr_bldr_jump, 4); len += 4;
            } else {
                memcpy(&buf[len], &msg->set_params.lk.ptr_mt_part_generic_read, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.ptr_mt_part_get_partition, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.bootimg_scratch_addr, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.bootimg_scratch_size, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.ptr_boot_linux, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.dtb_addr, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.dtb_space, 4); len += 4;
            }
            break;
        default:
            return -1;
    }

    // 長さプレフィックス
    uint32_t size = len;
    uint8_t size_buf[4] = {(size >> 24) & 0xff, (size >> 16) & 0xff, (size >> 8) & 0xff, size & 0xff};
    serial_write(p->io, size_buf, 4);
    serial_write(p->io, buf, len);
    return 0;
}

int protocol_read_message(protocol_t *p, message_t *msg) {
    uint8_t size_buf[4];
    if (serial_read(p->io, size_buf, 4, 5000) != 0) return -1;
    uint32_t size = (size_buf[0] << 24) | (size_buf[1] << 16) | (size_buf[2] << 8) | size_buf[3];
    if (size > sizeof(p->buf)) return -1;

    if (serial_read(p->io, p->buf, size, 5000) != 0) return -1;

    uint32_t off = 0;
    msg->type = p->buf[off++];

    switch (msg->type) {
        case MSG_ACK:
            break;
        case MSG_READ:
            memcpy(&msg->read.addr, &p->buf[off], 4); off += 4;
            memcpy(&msg->read.size, &p->buf[off], 4); off += 4;
            break;
        case MSG_WRITE:
            memcpy(&msg->write.addr, &p->buf[off], 4); off += 4;
            memcpy(&msg->write.size, &p->buf[off], 4); off += 4;
            break;
        case MSG_FLUSH_CACHE:
            memcpy(&msg->flush_cache.addr, &p->buf[off], 4); off += 4;
            memcpy(&msg->flush_cache.size, &p->buf[off], 4); off += 4;
            break;
        case MSG_JUMP:
            memcpy(&msg->jump.addr, &p->buf[off], 4); off += 4;
            memcpy(&msg->jump.r0, &p->buf[off], 4); off += 4;
            memcpy(&msg->jump.r1, &p->buf[off], 4); off += 4;
            msg->jump.has_r0 = p->buf[off++];
            msg->jump.has_r1 = p->buf[off++];
            break;
        case MSG_HOOK:
            msg->hook = p->buf[off++];
            break;
        case MSG_GET_FREE_RANGE:
            memcpy(&msg->get_free_range.size, &p->buf[off], 4); off += 4;
            if (size < off + 4) return -1;
            memcpy(&msg->get_free_range.min_addr, &p->buf[off], 4); off += 4;
            break;
        case MSG_BLACKLIST_RANGE:
            memcpy(&msg->blacklist.start, &p->buf[off], 4); off += 4;
            memcpy(&msg->blacklist.end, &p->buf[off], 4); off += 4;
            break;
        case MSG_SET_PARAMS:
            msg->set_params.type = p->buf[off++];
            if (msg->set_params.type == PARAMS_PRELOADER) {
                memcpy(&msg->set_params.preloader.ptr_bldr_jump, &p->buf[off], 4); off += 4;
            } else {
                memcpy(&msg->set_params.lk.ptr_mt_part_generic_read, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.ptr_mt_part_get_partition, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.bootimg_scratch_addr, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.bootimg_scratch_size, &p->buf[off], 4); off += 4;
                if (size < off + 12) return -1;
                memcpy(&msg->set_params.lk.ptr_boot_linux, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.dtb_addr, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.dtb_space, &p->buf[off], 4); off += 4;
            }
            break;
        default:
            return -1;
    }
    return 0;
}

int protocol_send_response(protocol_t *p, const response_t *resp) {
    uint8_t buf[16];
    uint32_t len = 0;
    buf[len++] = resp->type;
    if (resp->type == 'N') {
        buf[len++] = resp->err;
    } else if (resp->type == 'R') {
        memcpy(&buf[len], &resp->addr, 4); len += 4;
    }
    uint32_t size = len;
    uint8_t size_buf[4] = {(size >> 24) & 0xff, (size >> 16) & 0xff, (size >> 8) & 0xff, size & 0xff};
    serial_write(p->io, size_buf, 4);
    serial_write(p->io, buf, len);
    return 0;
}

int protocol_read_response(protocol_t *p, response_t *resp) {
    for (;;) {
        uint8_t size_buf[4];
        if (serial_read(p->io, size_buf, 4, 5000) != 0) {
            protocol_flush_payload_log(p);
            return -1;
        }
        uint32_t size = (size_buf[0] << 24) | (size_buf[1] << 16) |
                        (size_buf[2] << 8) | size_buf[3];
        if (size == 0 || size > sizeof(p->buf)) {
            protocol_flush_payload_log(p);
            return -1;
        }
        if (serial_read(p->io, p->buf, size, 5000) != 0) {
            protocol_flush_payload_log(p);
            return -1;
        }

        uint32_t off = 0;
        resp->type = p->buf[off++];
        if (resp->type == RESP_LOG) {
            if (size > 1)
                protocol_append_payload_log(p, &p->buf[1], size - 1);
            continue;
        }
        if (resp->type == 'N') {
            if (size < 2) {
                protocol_flush_payload_log(p);
                return -1;
            }
            resp->err = p->buf[off++];
        } else if (resp->type == 'R') {
            if (size < 5) {
                protocol_flush_payload_log(p);
                return -1;
            }
            memcpy(&resp->addr, &p->buf[off], 4); off += 4;
        }
        protocol_flush_payload_log(p);
        return 0;
    }
}

// ヘルパー
void message_init_ack(message_t *m) { m->type = MSG_ACK; }
void message_init_read(message_t *m, uint32_t addr, uint32_t size) {
    m->type = MSG_READ; m->read.addr = addr; m->read.size = size;
}
void message_init_write(message_t *m, uint32_t addr, uint32_t size) {
    m->type = MSG_WRITE; m->write.addr = addr; m->write.size = size;
}
void message_init_flush_cache(message_t *m, uint32_t addr, uint32_t size) {
    m->type = MSG_FLUSH_CACHE; m->flush_cache.addr = addr; m->flush_cache.size = size;
}
void message_init_jump(message_t *m, uint32_t addr, uint32_t r0, uint32_t r1, int has_r0, int has_r1) {
    m->type = MSG_JUMP; m->jump.addr = addr; m->jump.r0 = r0; m->jump.r1 = r1;
    m->jump.has_r0 = has_r0; m->jump.has_r1 = has_r1;
}
void message_init_hook(message_t *m, hook_id_t hook) { m->type = MSG_HOOK; m->hook = hook; }
void message_init_get_free_range(message_t *m, uint32_t size, uint32_t min_addr) {
    m->type = MSG_GET_FREE_RANGE;
    m->get_free_range.size = size;
    m->get_free_range.min_addr = min_addr;
}
void message_init_blacklist(message_t *m, uint32_t start, uint32_t end) {
    m->type = MSG_BLACKLIST_RANGE; m->blacklist.start = start; m->blacklist.end = end;
}
void message_init_set_params_preloader(message_t *m, preloader_runner_params_t *p) {
    m->type = MSG_SET_PARAMS; m->set_params.type = PARAMS_PRELOADER; m->set_params.preloader = *p;
}
void message_init_set_params_lk(message_t *m, lk_runner_params_t *p) {
    m->type = MSG_SET_PARAMS; m->set_params.type = PARAMS_LK; m->set_params.lk = *p;
}
