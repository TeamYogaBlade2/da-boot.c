OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(start)

SECTIONS
{
    . = 0x0;
    _image_start = .;

    .text.start : {
        KEEP(*(.text.start))

        /*
         * Values here are link-time offsets from _image_start.
         * Keep the metadata inside .text.start so it is part of the
         * raw payload emitted by llvm-objcopy.
         */
        . = ALIGN(4);
        _runtime_info_start = .;
        LONG(_rel_dyn_start - _image_start)
        LONG(_rel_dyn_end - _image_start)
        LONG(_stack_top - _image_start)
        _runtime_info_end = .;
    }

    .text : {
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .got : {
        _got_start = .;
        *(.got .got.*)
        *(.igot.plt)
        _got_end = .;
    }

    /*
     * Keep the dynamic relocation table inside the raw image.  The
     * entry code applies R_ARM_RELATIVE relocations before entering C.
     */
    .rel.dyn : ALIGN(4) {
        _rel_dyn_start = .;
        *(.rel.dyn)
        _rel_dyn_end = .;
    }

    .data : {
        *(.data .data.*)
    }

    .params : {
        . = ALIGN(4);
        KEEP(*(.params))
    }

    .bss : {
        _bss_start = .;
        *(.bss .bss.*)
        _bss_end = .;
    }

    _image_end = .;
    _stack_top = ALIGN(_image_end, 8) + 0x1000;   /* 4KBスタック */
}
