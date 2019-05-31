BITS 64
section .text
global _start
_start:
mov rax, 1
mov rdi, 1
mov rsi, msg
mov rdx, msglen
syscall

mov rdi, [g]
mov rax, 60
syscall

section .data
global g
g: dq 30
msg: db "Hello, world!", 10
msglen: equ $ - msg
