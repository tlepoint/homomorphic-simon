#!/usr/bin/python

z = [1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1]

plain = [0x656b696c, 0x20646e75]
key = [0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918]


def S(x,i):
  return ((x<<i) ^ (x>>32-i)) & 0xffffffff



for i in range(4,44):
  tmp = S(key[i-1],29) ^ key[i-3]
  tmp2 = S(tmp,31)
  key.append(0xfffffffc ^ z[i-4] ^ tmp ^ tmp2 ^ key[i-4])


for i in range(44):
  print hex(key[i])
  
print '------------------'

l = plain[0]
r = plain[1]

print hex(l), hex(r)

for i in range(44):
  tmp = l
  l = r ^ (S(l,1) & S(l,8)) ^ S(l,2) ^ key[i]
  r = tmp
  print hex(l), hex(r)
