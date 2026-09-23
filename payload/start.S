.syntax unified
.arm

.section .text.start
.global start
start:
    adr r9, _image_start       @ PIC base register
    @ The payload is loaded at DA_ADDR while the linker base is 0.
    @ Rebase the link-time stack offset to the actual runtime address.
    ldr r0, =_stack_top
    add sp, r0, r9
    mov r0, r9                 @ main(uint32_t runtime_base)
    bl  main
    b   .
