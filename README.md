# da-boot.c

A C implementation for booting MediaTek binaries through the BootROM,
Preloader, and LK stages without flashing them to storage.

This project is a C implementation of the host-side parts required by
`mt6572-mainline/da-boot`. Its command-line interface intentionally follows
the command structure and option names used by the upstream project where
the C implementation provides the corresponding functionality.

The C implementation currently supports:

* Preloader boot
* LK boot
* Payload REPL
* ARM/Thumb analysis of Preloader and LK binaries
* MediaTek GFH and LK image parsing
* Multiple input binaries in Preloader mode

BootROM mode is not currently implemented by this C version.

## Requirements

You need:

* clang
* Capstone development files
* `make`
* a MediaTek device supported by the project
* a Preloader matching the exact target device
* the helper payload built from `payload/`

On Arch Linux:

```sh
sudo pacman -S clang capstone make
```

## Build

Build everything:

```sh
make
```

Clean build:

```sh
make clean
make
```

The resulting executable is:

```text
./da-boot
```

## Usage

The general command-line form is:

```text
./da-boot [options] <mode>
```

The available modes are:

```text
preloader
lk
repl
```

The Preloader must belong to the exact device being tested. Do not use a
Preloader from another device just because it uses the same MediaTek SoC.

Example:

```
unpack_bootimg --boot_img twrp.img

dd if=kernel of=kernel.zImage bs=512 skip=1
dd if=ramdisk of=ramdisk.cpio.gz bs=512 skip=1

./da-boot --preloader ../../b8000/stock_rom/4.4/preloader_blade10_row_wifi.bin --lk ../../b8000/stock_rom/4.4/lk.bin --dram-size-per-rank 0x20000000 --dram-ranks 2 --kernel ../twrp/out/kernel.zImage --ramdisk ../twrp/out/ramdisk.cpio.gz lk
```

## Common options

### Preloader

```text
-p, --preloader <file>
```

Path to the Preloader image.

This option is required for every currently supported mode.

For a raw Preloader without a recognizable image header:

```text
--preloader-addr <address>
```

specifies the base address used by the ARM analyzer.

When the Preloader contains a valid GFH header, the detected load address and
jump offset take precedence over this fallback address.

### LK

```text
-l, --lk <file>
```

Path to the LK image.

This option is required for `lk` mode.

When LK address extraction from the Preloader fails, the following option can
be used:

```text
--lk-addr <address>
```

### LK boot mode

```text
-m, --lk-mode <mode>
```

Selects the LK boot mode written to the MediaTek boot argument structure.

Supported values are:

```text
normal
meta
recovery
sw-reboot
factory
advmeta
ate-factory
alarm
fastboot
download
```

The default is:

```text
normal
```

### DRAM

LK mode requires both:

```text
-d, --dram-size-per-rank <size>
-n, --dram-ranks <count>
```

Addresses and sizes may be written in decimal or in the usual C integer
notation, for example:

```text
0x20000000
```

The current C implementation accepts up to four DRAM ranks because the boot
argument structure contains four rank-size entries.

### Input files

```text
-i, --input <file@address>
```

Specifies a binary to upload to a target memory address.

The option may be specified multiple times.

For example:

```sh
./da-boot \
  -p preloader.bin \
  -i first.bin@0x48000000 \
  -i second.bin@0x49000000 \
  -j 0x48000000 \
  preloader
```

The address is parsed using the same `PATH@ADDRESS` syntax as the upstream
project.

### Final jump address

```text
-j, --jump-address <address>
```

Specifies the address to jump to after input binaries have been uploaded in
Preloader mode.

An input upload address and the final jump address are intentionally separate.
The program does not assume that they are identical.

### Kernel and ramdisk

```text
-k, --kernel <file>
-r, --ramdisk <file>
```

These options are used by LK mode when creating a boot image with `mkbootimg`.

`--ramdisk` requires `--kernel`.

For example:

```sh
./da-boot \
  -p preloader.bin \
  -l lk.bin \
  -k zImage \
  -r initrd.img \
  --dram-size-per-rank 0x20000000 \
  --dram-ranks 2 \
  lk
```

When a prepared boot image is already available, use `--input` instead.

### Device tree

LK mode can also boot with a supplied Device Tree Blob:

```text
--dtb <file>
```

When `--dtb` is specified, da-boot installs a hook in the stock LK
`boot_linux()` path. LK still builds its normal ATAG list first; immediately
before it enters the kernel, the payload folds the ATAG memory, command line,
initrd and serial information into the supplied DTB and then enters the
original kernel entry using the ARM DT boot protocol (`r0 = 0`, `r1 = 0xffffffff`,
`r2 = DTB`).

The DTB is uploaded into a free DRAM range at or above `0x88000000`, then
blacklisted from subsequent payload allocations. The extra workspace is
intentional because ATAG-to-FDT conversion may need more space than the
original DTB.

### Payload override

The C implementation also provides:

```text
--payload <file>
```

This is a C-specific extension and is not part of the upstream Rust CLI.

The default is:

```text
payload/payload.bin
```

## Preloader mode

Preloader mode boots a binary after the target Preloader has initialized the
device.

### Leave the DA running

For debugging and payload development, the C implementation allows the
Preloader mode to stop after starting the DA without performing a final jump:

```sh
./da-boot \
  -p preloader.bin \
  preloader
```

This is a C-specific convenience feature.

### Boot a binary

When an input binary is supplied, `--jump-address` must also be provided:

```sh
./da-boot \
  -p preloader.bin \
  -i uboot.bin@0x48000000 \
  --jump-address 0x48000000 \
  preloader
```

Multiple files can be uploaded before the final jump:

```sh
./da-boot \
  -p preloader.bin \
  -i firmware.bin@0x48000000 \
  -i dtb.bin@0x49000000 \
  --jump-address 0x48000000 \
  preloader
```

The upload address is reserved from the payload allocator after the upload.

## LK mode

LK mode boots a target after the LK stage.

The required pieces are:

* a Preloader
* an LK image
* either a prepared boot image supplied with `--input` or a kernel supplied
  with `--kernel`
* DRAM size per rank
* DRAM rank count

### Prepared boot image

```sh
./da-boot \
  -p preloader.bin \
  -l lk.bin \
  -i boot.img@0x85000000 \
  --dram-size-per-rank 0x20000000 \
  --dram-ranks 1 \
  lk
```

The current C implementation uses the uploaded file as the prepared boot
image and obtains a free destination range through the DA protocol. The
`@address` syntax is retained for CLI compatibility; the LK path does not use
that address as the final boot-image destination.

Only one `--input` is accepted in LK mode.

### Build a boot image from kernel and ramdisk

```sh
./da-boot \
  -p preloader.bin \
  -l lk.bin \
  -k zImage \
  -r initrd.img \
  --dram-size-per-rank 0x20000000 \
  --dram-ranks 2 \
  lk
```

This requires `mkbootimg` to be installed.

The C implementation constructs the MediaTek kernel/rootfs image wrappers
used by the target LK before invoking `mkbootimg`.

## REPL mode

The payload REPL can be entered with:

```sh
./da-boot \
  -p preloader.bin \
  repl
```

The currently implemented commands are:

```text
ack
read <address> <size>
write <address> <data>
jump <address>
quit
```

Some REPL commands are still intentionally minimal and do not yet expose the
full DA protocol.

## Automatic image analysis

The active Preloader analyzer is `src/arm_analyzer.c`.

It operates on the executable image represented by the Preloader rather than
blindly relying on fixed offsets.

For supported binaries it attempts to extract:

* Preloader download callback
* Preloader upload callback
* Preloader bootloader jump callback
* DA RAM address
* LK base address

The analyzer uses instruction semantics and literal-pool references for the
supported compiler patterns.

For raw binaries without image metadata, an explicit
`--preloader-addr` may be required.

## LK image parsing

LK images are parsed using the MediaTek partition header.

When an image header is present, the actual partition contents are analyzed
instead of treating the whole container as executable code.

Raw LK binaries are also supported when the LK base address can be supplied
or extracted from the Preloader.

## Communication

The host side communicates with MediaTek BootROM/Preloader interfaces using
the protocol implementation under `src/mtk_protocol.c` and the DA RPC
implementation under `src/da_protocol.c`.

The program currently looks for a MediaTek serial device under:

```text
/dev/ttyACM*
/dev/ttyUSB*
```

and uses 921600 baud.

Device enumeration is intentionally simple and does not yet identify devices
by USB VID/PID.

## Troubleshooting

### The Preloader cannot be analyzed

Check that:

1. the Preloader belongs to the exact target device;
2. the image is not truncated;
3. a raw image has the correct `--preloader-addr`;
4. Capstone can disassemble the target code;
5. the executable content is present in the image being analyzed.

### LK base extraction fails

Try supplying:

```text
--lk-addr 0xXXXXXXXX
```

for the actual LK load address.

The value is only used as a fallback when automatic extraction does not
produce a base address.

### LK mode reports missing DRAM information

Both arguments are mandatory:

```sh
--dram-size-per-rank 0x20000000
--dram-ranks 1
```

The exact values must match the target hardware.

### The payload fails immediately

Verify that the payload was rebuilt:

```sh
make clean
make
```

Also verify that the payload contains the parameter marker expected by the C
host implementation.

### USB device detection selects the wrong serial device

The current C implementation scans `/dev/ttyACM*` and `/dev/ttyUSB*` and does
not filter on USB identifiers.

Disconnect unrelated serial adapters when testing, or adjust
`find_mtk_port()` for your host environment.

## Relationship to upstream da-boot

This project follows the command-line model of:

```text
https://github.com/mt6572-mainline/da-boot
```

where practical.

The intended mapping is:

```text
upstream             da-boot.c
---------------------------------------------
-p / --preloader    -p / --preloader
--preloader-addr    --preloader-addr
-l / --lk           -l / --lk
--lk-addr           --lk-addr
-m / --lk-mode      -m / --lk-mode
-d / --dram-size-per-rank
                    -d / --dram-size-per-rank
-n / --dram-ranks   -n / --dram-ranks
-k / --kernel       -k / --kernel
-r / --ramdisk      -r / --ramdisk
-i / --input        -i / --input
-j / --jump-address -j / --jump-address
preloader           preloader
lk                  lk
repl                repl
```

The following upstream functionality is not currently implemented by this C
version:

* BootROM mode
* `--crash`
* the full multi-stage upstream payload architecture
* the full REPL command set

The C implementation keeps its own payload and protocol implementation rather
than trying to duplicate the entire Rust project.

## Development notes

The active ARM analyzer is:

```text
src/arm_analyzer.c
```

The older analyzer implementation in:

```text
src/patcher.c
```

is retained for compatibility with existing interfaces but is no longer part
of the main analyzer build path.

When extending the project, prefer semantic extraction and explicit image
parsing over adding fixed offsets for individual firmware revisions.

## License

```
SPDX-License-Identifier: AGPL-3.0-or-later
```
