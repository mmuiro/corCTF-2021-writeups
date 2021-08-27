----
title: corCTF 2021 - LCG_k
date: Aug 25 2021
author: qopruzjf
tags: crypto
---

Note: This is the challenge author's writeup. It describes the intended solution; however, keep in mind there are likely unintendeds usable to solve as well.

# Challenge

> Can you sign my message for me?
>
> nc crypto.be.ax 6002

# Solution

Let's look at the source provided in `source.py`.

```python
from Crypto.Util.number import bytes_to_long, inverse
from hashlib import sha256
from secrets import randbelow
from private import flag
from fastecdsa.curve import P256

G = P256.G
N = P256.q

class RNG:
	def __init__(self, seed, A, b, p):
		self.seed = seed
		self.A = A
		self.b = b
		self.p = p

	def gen(self):
		out = self.seed
		while True:
			out = (self.A*out + self.b) % self.p
			yield out

def H(m):
	h = sha256()
	h.update(m)
	return bytes_to_long(h.digest())

def sign(m):
	k = next(gen)
	r = int((k*G).x) % N
	s = ((H(m) + d*r)*inverse(k, N)) % N
	return r, s

def verify(r, s, m):
	v1 = H(m)*inverse(s, N) % N
	v2 = r*inverse(s, N) % N
	V = v1*G + v2*pub
	return int(V.x) % N == r

seed, A, b = randbelow(N), randbelow(N), randbelow(N)
lcg = RNG(seed, A, b, N)
gen = lcg.gen()
d = randbelow(N)
pub = d*G
mymsg = b'i wish to know the ways of the world'

print('public key:', pub)
signed_hashes = []

for _ in range(4):
	m = bytes.fromhex(input('give me something to sign, in hex>'))
	h = H(m)
	if m == mymsg or h in signed_hashes:
		print("i won't sign that.")
		exit()
	signed_hashes.append(h)
	r, s = sign(m)
	print('r:', str(r))
	print('s:', str(s))
print('now, i want you to sign my message.')
r = int(input('give me r>'))
s = int(input('give me s>'))
if verify(r, s, mymsg):
	print("nice. i'll give you the flag.")
	print(flag)
else:
	print("no, that's wrong.")
```

We are given the ability to sign four distinct messages(without hash collision) using ECDSA over the `P256` curve, and then are asked to sign the message `msg = 'i wish to know the ways of the world'`, without being able to sign it using one of the four chances given. The issue here is that the `k` nonces are generated using an linear congruence generator(LCG), so they are closely related to each other. Then, it seems like the method of attack is to exploit the nonces' relationship to recover the private key, which we can then use to forge a signature for `msg`.

Let's start out by writing the values of `ri, si` for each message `mi` that we send.

```python
ri = x(k_i*G) % N
si = (H(mi) + d*ri)*k_i^-1 % N
```
with `k_{i+1} = A*k_i + b mod p`. The key here is that due to the nonce generation's nature, we are not introducing any new unknowns into our equations beyond the first. Normally, when you sign messages using ECDSA, a new unknown `k_i` is added to your system of equations; in this case, however, no matter how many messages we sign, the unknowns remain as `A, b, k1, d`, where `k1` is the `k1` used in signing the first message. Technically the other unknown is `seed` instead, but to simplify things a little, we treat the first nonce directly as an unknown. 

With four signatures, we get eight equations, although the `ri` equations are not very useful to us, since they take the the coordinate of an elliptic curve point. However, the four equations involving the `si`s are enough to solve. You can do this through the following method or through more thorough equation manipulation(basically, by hand). If you are interested in solutions where solvers did them by hand, I recommend checking out [Utaha](https://utaha1228.github.io/ctf-note/2021/08/22/corCTF-2021/) and [y011d4](https://blog.y011d4.com/20210823-corctf-writeup/)'s writeups(you may need a translator for the second one), where they describe the methods to do so. The following method is less nice in my opinion, but demonstrates the usage of a powerful mathematical tool.

First, I eliminated the unknown private key `d` from my equations, by using the following relation:
```python
(si*k_i - H(mi))*ri^-1 - (s_{i+1}*k_{i+1} + H(m_{i+1}))*r_{i+1}^-1 = d - d = 0 mod N
```
with
```
k1 = k1
k2 = A*k1 + b
k3 = (A^2)*k1 + A*b + b
k4 = (A^3)*k1 + (A^2)*b + A*b + b
```
all `mod N`.

This produces 3 equations in 3 unknowns. (It turns out this step wasn't needed, but I kept it in from when I was first trying things for a solve). For the appropriate values of the nonces, the expressions on the left hand sides evaluate to `0`, as we see. Normally, this would be four unknowns in three equations; but in this case, all nonces can be expressed in terms of `A, k1, b`, so it's only three unknowns. However, substituting those expressions in for the nonces and doing algebra manipulation may seem quite complicated. If possible, we'd like a simpler way to deal with them...

Notice that since each left hand side expression evaluated with the correct value of the nonces will evaluate to `0`, this means that the same will be true for the correct values of `A, k1, b`. Let's then treat each left hand expression as a multivariate polynomial `P_i(A, k1, b)` with roots at the the correct values for each variable.

Then, our three equations can be considered three polynomials that share the correct values of `A, k1, b` as roots. There is a powerful tool known as `Groebner Basis reduction` that takes a set of multivariate polynomials and outputs a set of "reduced" polynomials that share roots with the inputted ones, while often being simpler(i.e. having lower degree). Of course, there are lot more details, but this description should be sufficient to understand its usefulness(unfortunately, I'm not so familiar with the details of its workings). We will try to use it on our polynomials to produce a set of potentially simpler polynomials which we may be able to directly extract our desired roots.

Giving it a try yields polynomials of the following form:
```
b^2 + c1*b + c0
k1 + c3*b + c2
a + c5*b + c4
```
where the `c` terms are constants.

In particular, the first two are of use to us, as we can easily extract the roots of the first one to obtain candidates for `b`, and select one to solve for `k1` with a `50%` chance. Then, using the fact that
```python
s1 = (H(m1) + d*r1)*k1^-1 => (si*k1 - H(m1))*r1^-1 = d % N
```
we can recover `d`. Then, using an arbitrary `k` value, we can perform the same calculations done in `sign` to forge a valid signature for `msg`, and send the pair `r, s` to the server to get the flag.

Here is my script to do so:
```python
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
```
`corctf{r3l4ted_n0nce5_4re_d4n6er0us_fde6ebafa842716a}`

Thanks to players for trying out this challenge!