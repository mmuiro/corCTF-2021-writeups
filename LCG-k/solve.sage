import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from fastecdsa.curve import P256

G = P256.G
N = P256.q
count = 4

Fn = GF(N)

def H(m):
	h = sha256()
	h.update(m)
	return bytes_to_long(h.digest())

host, port = 'crypto.be.ax', 6002
r = remote(host, port)
ms = [hex(i)[2:].zfill(2).encode() for i in range(count)]
zs = [Fn(H(ms[i])) for i in range(count)]
rs = []
ss = []

for i in range(count):
	r.recvuntil(b'give me something to sign, in hex>')
	r.sendline(ms[i].hex())
	r.recvuntil(b'r:')
	rs.append(Fn(int(r.recvline())))
	r.recvuntil(b's:')
	ss.append(Fn(int(r.recvline())))

P.<k, a, b> = PolynomialRing(Fn)

def lcg(x):
	return a*x + b

ks = [k]
for _ in range(count-1):
	ks.append(lcg(ks[-1]))

polys = [ss[i]*ks[i]*rs[i]^-1 - zs[i]*rs[i]^-1 -ss[i+1]*ks[i+1]*rs[i+1]^-1 + zs[i+1]*rs[i+1]^-1 for i in range(count-1)]
I = ideal(polys)
B = I.groebner_basis()
c0s = B[0].coefficients()
c1s = B[1].coefficients()
T.<x> = PolynomialRing(Fn, 'x')
poly = c0s[0]*x^2 + c0s[1]*x + c0s[2]
roots = poly.roots()
# 50-50 here
b = roots[0][0]
print(roots)
k1 = -(c1s[1]*b + c1s[2])*(c1s[0]^-1) % N
d = ((ss[0]*k1 - zs[0])*(rs[0]^-1)) % N

msg = b'i wish to know the ways of the world'
fr = (int(2)*G).x % N
fs = ((H(msg) + d*fr)*inverse_mod(2, N)) % N

r.recvuntil(b'give me r>')
r.sendline(str(fr))
r.recvuntil(b'give me s>')
r.sendline(str(fs))

r.interactive()