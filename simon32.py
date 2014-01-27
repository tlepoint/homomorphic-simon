#!/usr/bin/python


z = [1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0]
plain = [0x6565, 0x6877]
key = [0x0100, 0x0908, 0x1110, 0x1918]



def S(x,i):
  return ((x<<i) ^ (x>>16-i)) & 0xffff



for i in range(4,32):
  tmp = S(key[i-1],13) ^ key[i-3]
  tmp2 = S(tmp,15)
  key.append(0xfffc ^ z[i-4] ^ tmp ^ tmp2 ^ key[i-4])


for i in range(32):
  print hex(key[i])
  
print '------------------'

l = plain[0]
r = plain[1]

print hex(l), hex(r)

for i in range(32):
  tmp = l
  l = r ^ (S(l,1) & S(l,8)) ^ S(l,2) ^ key[i]
  r = tmp
  print hex(l), hex(r)
