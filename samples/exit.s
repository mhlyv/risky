; compile and link:
; nasm -felf64 exit.s
; ld -o exit exit.o

section .text
global _start
_start:
        mov edi, 42  ; return code 42
        mov eax, 60  ; `_exit` syscall
        syscall
