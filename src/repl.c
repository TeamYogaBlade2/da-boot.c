#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "serial.h"
#include "da_protocol.h"

int run_repl_mode(serial_t *s) {
    printf("REPL mode (type 'quit' to exit)\n");
    // 簡易REPL
    char line[256];
    protocol_t proto;
    protocol_init(&proto, s);

    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        // 改行除去
        line[strcspn(line, "\n")] = '\0';

        if (strcmp(line, "quit") == 0) break;
        if (strcmp(line, "ack") == 0) {
            message_t msg;
            message_init_ack(&msg);
            protocol_send_message(&proto, &msg);
            response_t resp;
            protocol_read_response(&proto, &resp);
            printf("Response: %c\n", resp.type);
        } else if (strncmp(line, "read ", 5) == 0) {
            uint32_t addr, size;
            if (sscanf(line+5, "%x %x", &addr, &size) == 2) {
                message_t msg;
                message_init_read(&msg, addr, size);
                protocol_send_message(&proto, &msg);
                // データ受信
                response_t resp;
                protocol_read_response(&proto, &resp);
                // 実装省略
            }
        } else if (strncmp(line, "write ", 6) == 0) {
            // 実装省略
        } else if (strncmp(line, "jump ", 5) == 0) {
            uint32_t addr;
            if (sscanf(line+5, "%x", &addr) == 1) {
                message_t msg;
                message_init_jump(&msg, addr, 0, 0, 0, 0);
                protocol_send_message(&proto, &msg);
                response_t resp;
                protocol_read_response(&proto, &resp);
                printf("Response: %c\n", resp.type);
            }
        } else {
            printf("Commands: ack, read <addr> <size>, write <addr> <data>, jump <addr>, quit\n");
        }
    }
    return 0;
}
