# da-boot.c

A C implementation for booting a MediaTek Download Agent (DA) through the BootROM, Preloader, and LK stages.

This version replaces the previous hard-coded Preloader/LK offsets with an ARM/Thumb analyzer built on top of Capstone. The analyzer extracts the addresses needed by the DA boot flow from the actual binary layout.

## Requirements

* clang or GCC
* Capstone and its development headers
* A MediaTek device and a compatible Preloader
* A payload at `payload/payload.bin` (or a path supplied with `--payload`)

On Debian/Ubuntu, for example:

```sh
sudo apt install clang libcapstone-dev
```

On Arch Linux:

```sh
sudo pacman -S clang capstone
```

## Build

```sh
make
```

For a clean rebuild:

```sh
make clean
make
```

## Usage

Basic Preloader mode:

```sh
./da-boot --preloader path/to/preloader.bin
```

LK mode requires an LK image and DRAM configuration:

```sh
./da-boot \
  --preloader path/to/preloader.bin \
  --lk path/to/lk.bin \
  --dram-size 0x10000000 \
  --dram-ranks 2
```

To provide a boot image directly:

```sh
./da-boot \
  --preloader path/to/preloader.bin \
  --lk path/to/lk.bin \
  --input path/to/boot.img@0x48000000 \
  --dram-size 0x10000000 \
  --dram-ranks 2
```

Run `./da-boot --help` to see the available options.

## Automatically Extracted Values

`src/arm_analyzer.c` extracts the addresses needed by the boot flow from the Preloader and LK images.

### Preloader

* USB download/upload callbacks: `ptr_dl`, `ptr_ul`
* Bootloader jump function: `bldr_jump`
* DA RAM address: `da_addr`
* LK base address: `lk_base`

When a Preloader contains a GFH header, `image_parse_preloader()` strips the image container and uses `load_addr + jump_offset` as the analysis base address. Raw binaries fall back to the supplied base hint.

### LK

* `mt_part_generic_read`
* `mt_part_get_partition`

LK images are also reduced to their executable content before analysis when an image header is present.

## ARM Analyzer

The old `src/patcher.c` implementation used several brittle heuristics: it treated a PC-relative `LDR` displacement as if it were the target address, searched only a few preceding instructions for `MOVW`/`MOVT`, and guessed function boundaries from nearby `PUSH`/`POP` instructions. Such assumptions can fail when compiler output or link layout changes.

The current analyzer performs a more semantic subset of the analysis required by the upstream project:

* resolves PC-relative literal loads and reads the actual literal-pool value
* matches references against the value stored in the literal pool instead of the pool address itself
* estimates function ranges using `PUSH`, `POP`, and `BX LR`
* tracks register definitions backwards
* reconstructs addresses produced by `MOV`, `MOVW`, `MOVT`, `ADR`, `ADD`, and `SUB`
* resolves values loaded through PC-relative and image-local `LDR` instructions
* narrows searches to candidate basic blocks
* tries both Thumb and ARM disassembly
* performs bounds checks before reading values from the input image

This makes extraction independent of fixed instruction offsets for the supported patterns.

## Relationship to Upstream `da-boot`

The current `mt6572-mainline/da-boot` implementation has a dedicated ARM analysis component called `kaiko`. This C implementation keeps the existing project architecture and dependencies small by implementing only the data-flow and code-pattern analysis needed by the DA extractors on top of Capstone.

It is therefore **not a full replacement for `kaiko`**. In particular, complex control-flow merges, indirect branches, and arbitrary function-pointer data flow are not modeled completely.

## DA Address Detection

`bldr_jump` is derived from direct `BL`/`BLX` calls in the candidate basic block, using the last suitable call target as the jump function.

`da_addr` is selected from literal values referenced by the candidate block or function when the value is at least `0x40000000` and aligned to 4 KiB.

This is more constrained than the old implementation, which scanned the raw function bytes for any value matching that shape, but it is still a heuristic rather than complete semantic analysis. A new SoC or a substantially different Preloader may require an additional pattern extractor.

## Troubleshooting

If Preloader analysis fails:

1. Verify that the Preloader matches the target SoC.
2. For GFH-wrapped images, verify that `load_addr` and `jump_offset` are detected correctly.
3. For raw binaries, verify that the supplied base hint is correct.
4. Check that Capstone can disassemble the relevant region correctly in either ARM or Thumb mode.
5. Verify that the extracted `ptr_dl` and `ptr_ul` values are valid Thumb function pointers inside the analyzed image.

If LK analysis fails, verify the detected LK base and the executable content range. When automatic LK-base detection fails, the SoC database's `lk_base_hint` is used as a fallback.

## Development Notes

`src/patcher.c` is the old analyzer implementation and is no longer part of the build. The active implementation is consolidated in `src/arm_analyzer.c`.

When supporting another Preloader or SoC, prefer deriving values from instruction semantics, literal pools, and register data flow rather than adding another hard-coded binary offset.
