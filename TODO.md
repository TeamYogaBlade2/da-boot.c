# da-boot.c TODO

This document tracks remaining work identified during the main-branch review of the C implementation of `mt6572-mainline/da-boot`.

The current target is the Lenovo YOGA Tablet / MT6589 path. The goal is to keep the existing working MT6589 flow stable while documenting work needed for broader compatibility and feature parity.

## High priority

### 1. Implement BootROM mode

The C implementation currently supports Preloader, LK, and REPL modes, but not the direct BootROM flow.

Work needed:

* Implement the BootROM-side protocol flow.
* Support sending and jumping to the payload directly from BootROM.
* Add the crash-to-BootROM path where appropriate.
* Match the upstream Rust implementation's BootROM behavior without weakening the existing Preloader/LK paths.

### 2. Identify MediaTek USB devices by VID/PID

Device discovery currently scans `/dev/ttyACM*` and `/dev/ttyUSB*` and selects the first matching node.

Work needed:

* Identify MediaTek USB serial interfaces using USB VID/PID information.
* Distinguish BootROM and Preloader modes where the USB identifiers allow it.
* Avoid accidentally opening an unrelated serial device when multiple USB serial devices are present.
* Keep a fallback path only if there is a documented reason to support devices without usable USB metadata.

## Compatibility and architecture

### 3. Generalize LK mode beyond MT6589

LK mode is intentionally restricted to MT6589 at the moment, while the SoC database contains other SoCs.

The current LK implementation still depends on MT6589-specific behavior, including:

* fixed kernel and ramdisk load addresses;
* MT6589-specific boot-image handling;
* MT6589-specific `mt_part_generic_read` / partition handling;
* MT6589-specific boot argument details.

Work needed:

* Define a per-SoC LK backend or capability model.
* Move SoC-specific constants out of the generic LK path.
* Add support for additional SoCs only when their LK ABI and image-loading behavior have been verified.
* Do not assume that the same kernel/ramdisk addresses or hook ABI apply to other MediaTek generations.

### 4. Support non-uniform DRAM ranks

The CLI currently exposes one `--dram-size-per-rank` value and applies it to every rank.

This is sufficient for symmetric configurations such as the YOGA Tablet's 512 MiB + 512 MiB layout, but it cannot represent configurations such as 1 GiB + 512 MiB.

Work needed:

* Add a way to specify the size of each rank independently.
* Preserve the existing symmetric CLI for compatibility if practical.
* Validate rank count and rank-size combinations against the target SoC.
* Propagate the per-rank topology consistently to the LK boot argument and payload memory management.

## Payload memory management

### 5. Make payload memory limits follow the requested DRAM configuration safely

The payload allocator must never expose memory outside the actually usable DRAM range.

Current MT6589 work should continue to support:

* 512 MiB: `0x80000000 .. 0xa0000000`
* 1 GiB: `0x80000000 .. 0xc0000000`

Work needed:

* Keep total-size calculations overflow-safe.
* Reject configurations that cannot be represented safely in the 32-bit address space.
* When per-rank sizing is implemented, derive the usable range from the actual rank layout rather than assuming equal ranks.
* Keep the payload's safe relocation/allocator strategy separate from the DRAM topology reported to LK.

## Analyzer robustness

### 6. Strengthen binary address/function extraction

The C implementation uses static analysis and data-flow heuristics to locate functions and addresses in Preloader/LK images.

Some paths intentionally have fallback heuristics because real vendor binaries vary, but the local data-flow resolver can still select a definition from an unrelated basic block in ambiguous cases.

Work needed:

* Prefer semantic anchors over generic instruction-pattern matching.
* Constrain extracted addresses to the analyzed image and expected address ranges.
* Add validation of surrounding call/data-reference relationships before accepting an extracted address.
* Add regression fixtures for the known Lenovo MT6589 JB/KK binaries.
* Keep fallback heuristics explicit and well documented.

## Protocol and runtime features

### 7. Expand REPL protocol coverage

The REPL is intentionally minimal compared with the full DA protocol.

Work needed:

* Implement missing useful commands.
* Add complete handling for read-data responses.
* Expose cache-control, range-management, and other protocol operations as appropriate.
* Keep malformed-message handling strict and consistent with the main boot paths.

### 8. Verify USB callback ABI details across supported Preloader/LK variants

The payload invokes function pointers supplied by the host for USB download/upload operations. The exact callback ABI and return-value semantics are vendor-specific.

Work needed:

* Verify the callback calling convention and return semantics against representative MT6589 binaries.
* Document the ABI assumptions in the payload code.
* Add runtime sanity checks where possible without breaking compatibility.

## Host-side cleanup and portability

### 9. Replace `system()` with direct process execution

The LK path currently invokes `mkbootimg` through the shell.

The temporary-path handling has been hardened, but invoking an external command through `system()` is still unnecessarily indirect.

Work needed:

* Use `fork`/`exec` (or an equivalent direct process API).
* Pass arguments as an argument vector rather than constructing a shell command string.
* Preserve the current temporary-file cleanup behavior.

### 10. Improve platform portability and error reporting

The current implementation primarily targets Linux with Linux-style serial devices and MediaTek USB flows.

Work needed:

* Make platform assumptions explicit in the build system and documentation.
* Improve diagnostics for serial, USB, and protocol failures.
* Keep timeout and I/O behavior deterministic across supported libc/kernel environments.

## Validation

### 11. Add reproducible integration/regression tests

The project has several binary-analysis and protocol paths whose correctness depends on real vendor images.

Work needed:

* Add fixture-based tests for Preloader and LK address extraction.
* Add protocol parser tests for truncated and malformed frames.
* Add allocator/range tests for 512 MiB, 1 GiB, boundary, and overflow cases.
* Add tests covering boot argument serialization and structure sizes.
* Where possible, document physical-device validation results separately from unit tests.

### 12. Validate additional MT6589 memory configurations

At minimum, the following should be tested before claiming broader MT6589 DRAM compatibility:

* 512 MiB, one rank;
* 1 GiB, two symmetric ranks;
* asymmetric-rank configurations once per-rank sizing is implemented.

Validation should confirm both LK's `dram_rank_*` fields and the payload allocator's usable range.

## Known scope limitations

The following are deliberately outside the current main-branch scope and should not be mixed into unrelated fixes:

* DTB/ATAGS-to-FDT boot support belongs to the `dtb` workstream.
* Direct BootROM support is a separate feature from the current Preloader/LK implementation.
* Non-uniform rank sizing requires a CLI/API change and should be implemented as a focused change rather than inferred from the current symmetric interface.
