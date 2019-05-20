BITS 64
section .text
global _start
_start:
mov bl, 42
xor eax, eax
inc eax
int 0x80
