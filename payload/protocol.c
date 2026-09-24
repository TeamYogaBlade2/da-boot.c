#include "protocol.h"
#include "libc_min.h"

void protocol_init(protocol_t *p, int (*send_fn)(const uint8_t*, uint32_t),
                   int (*recv_fn)(uint8_t*, uint32_t, uint32_t)) {
    p->send = send_fn;
    p->recv = recv_fn;
}

static int send_all(protocol_t *p, const uint8_t *data, uint32_t len) {
    return p->send(data, len);
}

static int recv_all(protocol_t *p, uint8_t *data, uint32_t len, uint32_t timeout) {
    return p->recv(data, len, timeout);
}

static int message_min_size(const uint8_t *buf, uint32_t size) {
    if (!buf || size < 1)
        return -1;

    switch (buf[0]) {
        case MSG_ACK:
            return 1;
        case MSG_READ:
        case MSG_WRITE:
        case MSG_FLUSH_CACHE:
        case MSG_BLACKLIST_RANGE:
            return 9;
        case MSG_JUMP:
            return 15;
        case MSG_HOOK:
            return 2;
        case MSG_GET_FREE_RANGE:
            return 5;
        case MSG_SET_PARAMS:
            if (size < 2)
                return -1;
            if (buf[1] == PARAMS_PRELOADER)
                return 6;
            if (buf[1] == PARAMS_LK)
                return 18;
            return -1;
        default:
            return -1;
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
            buf[len++] = msg->jump.has_r0;
            buf[len++] = msg->jump.has_r1;
            break;
        case MSG_HOOK:
            buf[len++] = msg->hook;
            break;
        case MSG_GET_FREE_RANGE:
            memcpy(&buf[len], &msg->get_free_range.size, 4); len += 4;
            break;
        case MSG_BLACKLIST_RANGE:
            memcpy(&buf[len], &msg->blacklist.start, 4); len += 4;
            memcpy(&buf[len], &msg->blacklist.end, 4); len += 4;
            break;
        case MSG_SET_PARAMS:
            buf[len++] = msg->set_params.type;
            if (msg->set_params.type == PARAMS_PRELOADER) {
                memcpy(&buf[len], &msg->set_params.preloader.ptr_bldr_jump, 4); len += 4;
            } else if (msg->set_params.type == PARAMS_LK) {
                memcpy(&buf[len], &msg->set_params.lk.ptr_mt_part_generic_read, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.ptr_mt_part_get_partition, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.bootimg_scratch_addr, 4); len += 4;
                memcpy(&buf[len], &msg->set_params.lk.bootimg_scratch_size, 4); len += 4;
            } else {
                return -1;
            }
            break;
        default:
            return -1;
    }

    // 長さをビッグエンディアンで送信
    uint32_t size_be = __builtin_bswap32(len);
    if (send_all(p, (uint8_t*)&size_be, 4) != 0) return -1;
    return send_all(p, buf, len);
}

int protocol_read_message(protocol_t *p, message_t *msg) {
    uint8_t size_buf[4];
    int min_size;

    if (recv_all(p, size_buf, 4, 0) != 0) return -1;
    uint32_t size = __builtin_bswap32(*(uint32_t*)size_buf);
    if (size > sizeof(p->buf)) return -1;
    if (recv_all(p, p->buf, size, 0) != 0) return -1;

    min_size = message_min_size(p->buf, size);
    if (min_size < 0 || size < (uint32_t)min_size)
        return -1;

    memset(msg, 0, sizeof(*msg));

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
            break;
        case MSG_BLACKLIST_RANGE:
            memcpy(&msg->blacklist.start, &p->buf[off], 4); off += 4;
            memcpy(&msg->blacklist.end, &p->buf[off], 4); off += 4;
            break;
        case MSG_SET_PARAMS:
            msg->set_params.type = p->buf[off++];
            if (msg->set_params.type == PARAMS_PRELOADER) {
                memcpy(&msg->set_params.preloader.ptr_bldr_jump, &p->buf[off], 4); off += 4;
            } else if (msg->set_params.type == PARAMS_LK) {
                memcpy(&msg->set_params.lk.ptr_mt_part_generic_read, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.ptr_mt_part_get_partition, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.bootimg_scratch_addr, &p->buf[off], 4); off += 4;
                memcpy(&msg->set_params.lk.bootimg_scratch_size, &p->buf[off], 4); off += 4;
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
    if (resp->type == RESP_NACK) {
        buf[len++] = resp->err;
    } else if (resp->type == RESP_RANGE) {
        memcpy(&buf[len], &resp->addr, 4); len += 4;
    }
    uint32_t size_be = __builtin_bswap32(len);
    if (send_all(p, (uint8_t*)&size_be, 4) != 0) return -1;
    return send_all(p, buf, len);
}

int protocol_read_response(protocol_t *p, response_t *resp) {
    uint8_t size_buf[4];
    if (recv_all(p, size_buf, 4, 0) != 0) return -1;
    uint32_t size = __builtin_bswap32(*(uint32_t*)size_buf);
    if (size == 0 || size > sizeof(p->buf)) return -1;
    if (recv_all(p, p->buf, size, 0) != 0) return -1;

    memset(resp, 0, sizeof(*resp));
    uint32_t off = 0;
    resp->type = p->buf[off++];
    if (resp->type == RESP_NACK) {
        if (size < 2) return -1;
        resp->err = p->buf[off++];
    } else if (resp->type == RESP_RANGE) {
        if (size < 5) return -1;
        memcpy(&resp->addr, &p->buf[off], 4); off += 4;
    } else if (resp->type != RESP_ACK && resp->type != RESP_DATA) {
        return -1;
    }
    return 0;
}
