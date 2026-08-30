CC = clang
OBJCOPY = llvm-objcopy
TARGET_TRIPLE = arm-none-eabi

CFLAGS = --target=$(TARGET_TRIPLE) \
         -mcpu=cortex-a7 \
         -mthumb \
         -fPIC \
         -ffreestanding \
         -nostdlib \
         -fno-builtin \
         -Wall \
         -O2 \
         -ffunction-sections \
         -fdata-sections \
         -I. \
         -MMD -MP

LDFLAGS = --target=$(TARGET_TRIPLE) \
          -fuse-ld=lld \
          -Tlinker.ld \
          -nostdlib \
          -Wl,--gc-sections

SRCS = main.c usb.c protocol.c interceptor.c bump_alloc.c cache.c libc_min.c params.c start.S

C_OBJS = $(filter %.o, $(SRCS:.c=.o))
S_OBJS = $(filter %.o, $(SRCS:.S=.o))
OBJS = $(C_OBJS) $(S_OBJS)

DEPS = $(OBJS:.o=.d)
TARGET = payload.bin

all: $(TARGET)

$(TARGET): payload.elf
	$(OBJCOPY) -O binary $< $@

payload.elf: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) payload.elf payload.bin

.PHONY: all clean
