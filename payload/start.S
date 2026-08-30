.syntax unified
.arm

.section .text.start
.global start
start:
    adr r9, _image_start       @ PIC base register
    ldr sp, =_stack_top
    bl  main
    b   .
