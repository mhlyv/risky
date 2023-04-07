; compile and link:
; nasm -felf64 exit.s
; ld -o exit exit.o

section .text
global _start
_start:
    sub rsp, 10
    mov byte [rsp+0], 'H'
    mov byte [rsp+1], 'i'
    mov byte [rsp+2], '!'
    mov byte [rsp+3], 10

    mov edi, 1  ; stdout
    mov rsi, rsp
    mov rdx, 4
    mov eax, 1  ; write
    syscall
    
    add rsp, 10

    xor edi, edi
    mov eax, 60  ; exit
    syscall
