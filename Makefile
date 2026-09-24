CC = clang
CFLAGS = -Wall -Wextra -O2 -Iinclude -Icommon -MMD -MP
LDFLAGS = -lcapstone

SRCS = src/main.c src/serial.c src/mtk_protocol.c src/da_protocol.c \
       src/arm_analyzer.c src/soc_db.c src/boot_preloader.c src/boot_lk.c \
       src/repl.c src/image.c src/util.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = da-boot

all: $(TARGET) payload

payload:
	$(MAKE) -C payload

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
	$(MAKE) -C payload clean

.PHONY: all clean payload
