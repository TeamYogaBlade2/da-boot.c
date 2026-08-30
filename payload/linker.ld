OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(start)

SECTIONS
{
    . = 0x0;
    _image_start = .;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        _bss_start = .;
        *(.bss .bss.*)
        _bss_end = .;
    }

    _image_end = .;
    _stack_top = . + 0x1000;   /* 4KBスタック */
}
