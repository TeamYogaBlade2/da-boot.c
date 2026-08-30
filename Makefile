CC = clang
CFLAGS = -Wall -Wextra -O2 -Iinclude -MMD -MP
LDFLAGS = -lcapstone

SRCS = src/main.c src/serial.c src/mtk_protocol.c src/da_protocol.c \
       src/patcher.c src/soc_db.c src/boot_preloader.c src/boot_lk.c \
       src/repl.c src/image.c src/util.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = da-boot

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

.PHONY: all clean
