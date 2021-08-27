----
title: corCTF 2021 - fried_rice
date: Aug 23 2021
author: qopruzjf
tags: crypto
---

Note: This is the challenge author's writeup. It describes the intended solution; however, keep in mind there are likely unintendeds usable to solve as well.

# Challenge

> Kind of hungry... guess I'll make some fried rice.
> NOTE: The server has a time limit of 5 minutes.
>
> nc crypto.be.ax 6003

# Solution

Let's examine the source given in `source.sage` first.
```python
from random import shuffle, randrange, randint
from os import urandom
from Crypto.Util.number import getPrime, getStrongPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from private import flag
import sys

class RNG:
	def __init__(self, seed, a, b):
		self.state = seed
		self.a = a
		self.b = b
		print('a:', a)
		print('b:', b)

	def nextbits(self, bitlen):
		out = 0
		for _ in range(bitlen):
			out <<= 1
			self.state = self.a * self.state + b
			bit = int(sum(self.state[i] for i in range(7)))
			out += bit
		return out

def get_params(rng, bitlen):
	p = next_prime((1 << (bitlen - 1)) | rng.nextbits(bitlen))
	q = next_prime((1 << (bitlen - 1)) | rng.nextbits(bitlen))
	N = p * q
	return N, p, q

LIMIT = 26
P.<x> = PolynomialRing(GF(2))
F.<x> = P.quo(x^128 + x^7 + x^2 + x + 1)
key, a, b = [F.random_element() for _ in range(3)]
bytekey = long_to_bytes(int(''.join(list(map(str, key.list()))), 2))
iv = os.urandom(16)
cipher = AES.new(bytekey, AES.MODE_CBC, IV=iv)
rng = RNG(key, a, b)
N, p, q = get_params(rng, 512)
if randint(0, 1):
	p, q = q, p
e = 65537
d = inverse_mod(e, (p-1)*(q-1))
dp = d % (p-1)
r = getStrongPrime(1024)
g = randrange(2, r)
print('iv:', iv.hex())
print('N:', N)
print('e:', e)
print('g:', g)
print('r:', r)
print('encrypted flag:', cipher.encrypt(pad(flag, 16)).hex())
print()
print("now, let's cook some fried rice!")
for _ in range(LIMIT):
	sys.stdout.flush()
	m = int(input('add something in(in hex)> '), 16)
	dp ^^= m
	print('flip!', pow(g, dp, r))
print("it's done. enjoy your fried rice!")
```

The server generates a polynomial over the given quotient ring `F`, takes the coefficients of said polynomial as an AES key, and encrypts the flag using it. Then, using the PRNG described with `key` as the initial state, it generates 512 bits, each for use in primes `p` and `q`. The server then gives us the parameters `a` and `b` used in the PRNG, the `iv` used in the AES encryption, the number `N = p * q`, the public exponent `e` used to calculate `d`, and the numbers `g` and `r`. It then takes `26` inputs from the user, updates the value `dp`, initially equal to `d % (p-1)`, by XORing it with the user's input. (If you are not familiar with sagemath, `^` can be used for exponentiation, and `^^` is used for bitwise XOR.)

The end goal of the challenge is to recover `bytekey`. So, it seems that we need to somehow use the `26` queries to get information to factor `N`, and then with knowledge of `p` and `q`'s bits, reverse the PRNG to recover `key`, which will give us `bytekey`.

## Stage 1: Recovering bits of `dp`

First, let's focus on the `26` queries with the server, and what we can do with them. Since the server will update `dp XOR m` for every `m` you send and the print `g^dp mod r`, it's like that we are supposed to use these queries to recover some amount, if not all, of `dp`. Assuming we can't just solve the discrete log problem(DLP), we will need to find some way to do this.

(As a side note, it is actually possible to solve the DLP, in some situations. This is because `getStrongPrime` returns a prime `r` such that `r-1` and `r+1` have at least one large prime factor. However, this is not nearly as secure as a **safe prime**, which is a prime of the form `r = 2p + 1`, where `p` is another prime. This was pointed out to me by a solver during the CTF. So, it is possible for `r` to be generated such that it is smooth enough to be attacked using the Pohlig-Hellman algorithm. You just need some luck. The attack taking advantage of this is in my opinion much cooler than my solution, so I suggest you read `joseph` from `skateboarding dog`'s [writeup](https://jsur.in/posts/2021-08-23-corctf-2021-fried-rice-writeup) about it.)

To illustrate my method of attack, let's consider the numbers `dp` and `dp1 = dp XOR 1`. When let's define `v1 = g^dp mod r`, and `v2 = g^dp1 mod r`. Now, consider the following two cases:

- `dp` is odd - then `dp1 = dp - 1`, as the last bit of `dp` is `1`. Then, `v2 = g^(dp - 1) = g^dp * g^-1 = v1 * g^-1 mod r`.
- `dp` is even - then `dp1 = dp + 1`, as the last bit of `dp` is `0`. Then, `v2 = g^(dp + 1) = g^dp * g = v1 * g mod r`.

Putting this into context of this challenge, suppose we first send `0` as `m` so that we retrieve `v1 = g^dp mod r`. Then, we can send `1` as `m`, so that we get `v2 = g^(dp XOR 1) mod r`. Then, simply checking if `v2 = v1 * g^-1 mod r` or `v2 = v1 * g mod r` will reveal the last bit of `dp`.

We can further extend this idea to reveal other bits. For a bit that is `dis` bits away from the last bit, we can check `v1 = g^d1 mod r` versus `v2 = g^(d1 XOR (1 << dis)) mod r`. `d1 XOR (1 << dis)` will either be `1 << dis = 2^dis` added or subtracted from `d1`. So, we can similarly check whether `v2 = v1 * g^(2^dis) mod r` or `v2 = v1 * g^-(2^dis) mod r`. This gives us a method to leak any arbitrary bit of `dp`, simply by changing `dis` each time so that the original `dp` bit in that position is preserved before we attempt to leak it, even after `dp` is altered.

With this method, we can leak `25` bits of `dp`, in any positions. Note that the first query is used by sending `0` to get `g^dp mod r`. However, `25` bits of a `~512` bit number(since `dp` is the inverse of `e`, a relatively small number mod `p`, which is a `512` bit prime) is not very meaningful. We need some way to dramatically increase the number of bits we can leak.

We can do just this, simply by further expanding on the ideas we've developed so far. Let's consider how we can check `2` bit chunks at a time instead of 1. Now, the possible `2` bit states our target chunk could have are `00, 01, 10, 11`. If when XORed with `3`, which is `11` in binary, the possible resultant states are `11, 10, 01, 00`. These correspond to changes of `3, 1, -1, -3`. Notice that the changes are all unique, so just like before, we can check each difference to see what the original bits of the chunk were.

Naturally, we can expand this further. Consider a chunk `c` of bit length `l` that we would like to check. We send `m` as the base 10 equivalent of a binary string consisting of `l` `1`s. As long as the differences between all possible original states of `c` and `c XOR m` are unique, we can determine the original state of `c`, using a simple search through all the possible differences and the technique described above. Of course, when trying to find different chunks, we will need to account for bit positions they are in, just like before. And it's easy to check that all differences are unique simply by calculating them.

The main issue with this method is, for every increase in bitlength of the chunk, we double the search space that we go through. With the given time limit, we are unable to leak large chunks at a time using this method without some substantial luck. On my laptop, with the `25` queries after sending `m = 0`, I was able to recover `14` bit chunks, for a total of `350` bits of `dp`. I chose to recover the most significant bits, since they will the simplest to use for the next part of the challenge.

As a side note, if you are more creative, you may find a method to more efficiently leak each chunk than this naive method. With `20` bits per chunk, it is enough to recover the entirety of `dp` and partially skip the next step.

Here's the code to recover all but the bottom `168` bits of `dp`:

```python
def search_chunk(nbits, stage, cur, m):
	m = int(m << (stage * nbits))
	r.recvuntil(b'add something in(in hex)> ')
	r.sendline(hex(m)[2:].encode())
	r.recvuntil(b'flip! ')
	res = int(r.recvline())
	cands = [i for i in range(2**nbits)]
	ref = {}
	# setup
	for cand in cands:
		c = int(cand << (stage * nbits))
		diff = c - (c^^m)
		ref[diff] = cand
	# perform search
	for k, v in ref.items():
		if res * pow(g, k, rh) % rh == cur:
			return res, v


def recover_dp_MSBs(shift):
	dpmsbs = 0
	CHUNKSIZE = 14
	r.recvuntil(b'add something in(in hex)> ')
	r.sendline(b'00')
	r.recvuntil(b'flip! ')
	cur = int(r.recvline())
	m = 2**CHUNKSIZE - 1
	for i in range(LIMIT - 1):
		cur, chunk = search_chunk(CHUNKSIZE, i + shift, cur, m)
		dpmsbs += chunk << (CHUNKSIZE * i)
		print(f'completed stage {i+1}')
	return Integer(dpmsbs)

d0 = recover_dp_MSBs(12)
```


## Stage 2: Factoring `N` using MSBs of `dp` (Skip to next section if already familiar)

There is a known attack to factor `N` when you know enough MSBs of `dp = d mod (p-1)`. Relevant reading is [here](https://eprint.iacr.org/2020/1506.pdf). The explanation there is already quite good, but I'll try to explain the ideas used here in brief. Naturally, feel free to skip if you are familiar with this.

We start with the congruence `e*dp = 1 mod (p-1)`. Lifting to the integers, we have `e*dp = 1 + kp*(p-1)`. Because `dp < p - 1`, `kp < e`, or else `kp * (p-1) > e*dp` and the equality is not possible. So, we can bruteforce the value of `kp`, as `e` is small. Then, taking the equation `mod p` this time and moving all terms to the left side, we have `e*dp + kp - 1 = 0 mod p`.

Next, we include our known MSBs `a` into the expression. If the bottom `l` bits of `dp`, which we call `r`, are unknown, then we have `dp = a*(2^l) + r`, where `a`, `l` are known. Then, we have `e*(a*(2^l) + r) + kp - 1 = 0 mod p`. Note that `R = 2^l` is a upper bound for `r`, as `r` is `l` bits and `2^l` is `l+1` bits. Multiplying both sides by `einv = e^-1 mod N`, which is congruent to `e^-1 mod p`(I suggest trying to prove this yourself if this is not clear), we have `r + a*(2^l) + einv(kp - 1) = 0` mod p. Let's then define the value `A = a*(2^l) + einv(kp - 1)` and the polynomial `P(x) = x + A` in `mod p`, which has root `r`. Then, we need to find this root, which will allow us to calculate the quantity `r + A`, which, if it is a small multiple of `p`, will allow us to factor `N` via GCD.

The way we find this root will be to find it using another polynomial that also has it `r` as a root `mod p`. One way to construct such a polynomial is by constructing a polynomial that is a linear combination of other polynomials that have `r` as a root, because evaluating it at `r` will result in summing `0`s. Consider the polynomials `x*(x + A)`, `x + A`, and `N`. All of these share `r` as a root `mod p`(in the case of `N`, it is `0 mod p`, and the `0` polynomial has any value as a root). We construct the following matrix as a [lattice](https://cryptohack.gitbook.io/cryptobook/lattices/definitions) basis:

```
[[1, A, 0]
 [0, 1, A]
 [0, 0, N]]
```

where the columns correspond to the coefficient of `x^2`, `x`, and the constant from left to right, and each row corresponds to one of those polynomials. Then, any polynomial constructed by taking the coefficients from a vector in the lattice will also have root `r` in `mod p`.

Next, even though we do not know `p`, we want a polynomial where we can still extract `r` as a root. This means that we want our polynomial `f(x)` to have `f(r) = 0` over the integers, since that will also be `0 mod p`. Having a root `mod N` is not useful, as using GCD will simply return `N`.

To ensure that we can construct a polynomial with this property, we'll make one more modification to the above matrix, which is multiplying the columns by `R^2` and `R` for the first and second column, resulting in 
```
[[R^2, R*A, 0]
 [0, R, A]
 [0, 0, N]]
```
as the matrix. My understanding for this is that since `R > r`, we sort of 'evaluate' the polynomial at `R` in each row by doing this multiplication, and so the norm(refer to the paper for details, but it is untuitively connected to the length/magnitude) of that row acts as an upper bound on evaluating the polynomial at `r` instead. So, if we get the vector `v = (a1*R^2, a2*R, a3)`, if the norm of `v` is less than `p`, then the polynomial `f(x) = a1*x^2 + a2*x + a3` should have `r` as a root over the integers. To find `v` from the lattice, we can use LLL reduction, which will find it as long as `R` is not too big. This also fits the intuition that having too many unknown bits will result in failing to recover the appropriate root, and why we want to recover as many bits as possible from stage 1.

To recap, our approach for this part is as follows:

- For each possible value of `kp < e`, construct the aforementioned lattice
- LLL to recover the vector from which we construct the polynomial
- `r` is an integer, so get the integer roots from the polynomial
- for each root, calculate `A + r` and gcd with `N`. If greater than `1` and is less than `N`, then we have `p`, and we're done.

Here's the code for this stage:

```python
def factor_n_with_dpmsbs(cs, shift):
	l = cs * shift
	ei = inverse_mod(e, N)
	for kp in range(1, e):
		R = 2**l
		A = R * d0 + ei*(kp - 1)
		B = Matrix([
			[R**2, R*A, 0],
			[0, R, A],
			[0, 0, N]])
		B = B.LLL()
		vec = B[0]
		poly = (vec[0]/(R^2))*y^2 + (vec[1]/R)*y + vec[2]
		roots = poly.roots(multiplicities=False)
		for root in roots:
			ff = int(A + root)
			fac = gcd(ff, N)
			if fac > 1 and fac != N:
				print('found!')
				return fac, N / fac

p, q = factor_n_with_dpmsbs(14, 12)
```

# Stage 3: Recovering the initial state of the PRNG

With a method to factor `N` to get `p` and `q`, we need to recover `key` so that we can get the AES key.

Note: The PRNG used here is a slightly modified version of the one in `Phoenix` from `AeroCTF 2021`. Additionally, the solve is based off what I learned from [rkm0959's writeup](https://rkm0959.tistory.com/211) on that challenge. I highly recommend reading it, but I'll explain the ideas here.

Since `key` is an element in the given quotient ring, we can express what we want to find as the vector of `128` coefficients `[k127, k126, k125, ..., k0]` where each `ki` is one of `0, 1` and `key = k127*x^127 + k126*x^126 + ... + k1*x + k0`. If we can get a system of `128` linear equations involving these `128` unknowns, we can get the key to decrypt the flag. Then, let's consider how we can set up the system using the PRNG's workings.

The state of the PRNG simply starts out as `key`, but updates as follows:
```python
self.state = self.a * self.state + self.b
```
where the result is kept in `F`. Then, after updating, the coefficients of `x^6`, `x^5`, ..., `x`, and the constant are XORed together(addition in GF(2)), and the result is appended to the current output bits.

To consider how we can express each output bit in terms of our unknown coefficients, consider that:
`a*(k127*x^127 + k126*x^126 + ... + k1*x + k0) + b = k127*a*x^127 + k126*a*x^126 + .... + k1*a*x + k0*a + b`.
In other words, we can distribute `a` out to each of the individual monomials. Then, we'll consider each `monomial*a` individually. Because adding polynomials will just be adding the coefficients in `GF(2)` for each `x^i`, if we define `fi = ki*a*x^i`, then, for `state = a*(k127*x^127 + k126*x^126 + ... + k1*x + k0) + b`, we have:

`state[6] + state[5] + ... + state[0] = Sum(fi[6] + fi[5] + ... + fi[0]) + (b[6] + b[5] + ... + b[0]) = output[i]`, where the Sum is done over all `0 <= i < 128`, and the addition is done in `GF(2)`. Since `fi = ki*a*x^i`, `fi[6] + fi[5] + ... + fi[0] = ki*((a*x^i)[6] + (a*x^i)[5] + ... + (a*x^i)[0])`, meaning the previous equation gives us a linear equation in terms of `ki`, exactly what we wanted.

Naturally, we can extend this to subsequent states as well, since our states will look like:

```python
a*state + b
(a^2)*state + a*b + b
(a^3)*state + (a^2)*b + a*b + b
.
.
.
```
so we can apply the same idea, treating `a^i` as our `a` from before, and `b*(a^(i-1) + a^(i-2) + ... + 1)` as our `b` from before. 
We can get our output `128` bits from one of `p` or `q`(skipping the first bit since it was ORed with 1), solve the system of `128` linear equations, recover key, and try using it to decrypt the flag. If it decrypts successfully, then we're done.

Here's this stage's script:

```python
def recover_key_from_prime(p):
	stream = list(map(int, list(bin(p)[3:])))
	v = [a*(x^i) for i in range(KEYLEN)] # skip the first bit
	ext = b
	M = []
	vec = []
	for j in range(KEYLEN):
		v = [a*el for el in v]
		ext = a*ext + b
		M.append([int(sum(v[k][l] for l in range(7))) for k in range(KEYLEN)])
		out = int(sum(ext[l] for l in range(7))) ^^ stream[j]
		vec.append(out)
	M, vec = Matrix(GF(2), M), vector(GF(2), vec)
	key = M.solve_right(vec)
	key = long_to_bytes(int(''.join(list(map(str, [bit for bit in key]))), 2))
	print('got key!')
	return key


def recover_key_and_flag():
	key1 = recover_key_from_prime(p)
	key2 = recover_key_from_prime(q)
	for key in (key1, key2):
		try:
			cipher = AES.new(key, AES.MODE_CBC, IV=iv)
			flag = unpad(cipher.decrypt(enc), 16)
			print(flag)
		except:
			pass

```

and the final attack script:

```python
import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from time import time

host, port = '35.208.182.172', 6003
r = remote(host, port)

P.<x> = PolynomialRing(GF(2))
F.<x> = P.quo(x^128 + x^7 + x^2 + x + 1)
L.<y> = PolynomialRing(ZZ)

LIMIT = 26
e = 65537
KEYLEN = 128
a, b, iv, N, g, rh, enc = [None for _ in range(7)]

def get_params():
	global a, b, iv, N, g, rh, enc
	r.recvuntil(b'a: ')
	a = sage_eval(r.recvline().decode(), locals={'x':x})
	r.recvuntil(b'b: ')
	b = sage_eval(r.recvline().decode(), locals={'x':x})
	assert a in F and b in F
	r.recvuntil(b'iv: ')
	iv = bytes.fromhex(r.recvline().decode())
	r.recvuntil(b'N: ')
	N = int(r.recvline())
	r.recvuntil(b'e: ')
	e = int(r.recvline())
	r.recvuntil(b'g: ')
	g = int(r.recvline())
	r.recvuntil(b'r: ')
	rh = int(r.recvline())
	r.recvuntil(b'flag: ')
	enc = bytes.fromhex(r.recvline().decode())


def search_chunk(nbits, stage, cur, m):
	m = int(m << (stage * nbits))
	r.recvuntil(b'add something in(in hex)> ')
	r.sendline(hex(m)[2:].encode())
	r.recvuntil(b'flip! ')
	res = int(r.recvline())
	cands = [i for i in range(2**nbits)]
	ref = {}
	# setup
	for cand in cands:
		c = int(cand << (stage * nbits))
		diff = c - (c^^m)
		ref[diff] = cand
	# perform search
	for k, v in ref.items():
		if res * pow(g, k, rh) % rh == cur:
			return res, v


def recover_dp_MSBs(shift):
	dpmsbs = 0
	CHUNKSIZE = 14
	r.recvuntil(b'add something in(in hex)> ')
	r.sendline(b'00')
	r.recvuntil(b'flip! ')
	cur = int(r.recvline())
	m = 2**CHUNKSIZE - 1
	for i in range(LIMIT - 1):
		cur, chunk = search_chunk(CHUNKSIZE, i + shift, cur, m)
		dpmsbs += chunk << (CHUNKSIZE * i)
		print(f'completed stage {i+1}')
	return Integer(dpmsbs)


def factor_n_with_dpmsbs(cs, shift):
	l = cs * shift
	ei = inverse_mod(e, N)
	for kp in range(1, e):
		R = 2**l
		A = R * d0 + ei*(kp - 1)
		B = Matrix([
			[R**2, R*A, 0],
			[0, R, A],
			[0, 0, N]])
		B = B.LLL()
		vec = B[0]
		poly = (vec[0]/(R^2))*y^2 + (vec[1]/R)*y + vec[2]
		roots = poly.roots(multiplicities=False)
		for root in roots:
			ff = int(A + root)
			fac = gcd(ff, N)
			if fac > 1 and fac != N:
				print('found!')
				return fac, N / fac


def recover_key_from_prime(p):
	stream = list(map(int, list(bin(p)[3:])))
	v = [a*(x^i) for i in range(KEYLEN)] # skip the first bit
	ext = b
	M = []
	vec = []
	for j in range(KEYLEN):
		v = [a*el for el in v]
		ext = a*ext + b
		M.append([int(sum(v[k][l] for l in range(7))) for k in range(KEYLEN)])
		out = int(sum(ext[l] for l in range(7))) ^^ stream[j]
		vec.append(out)
	M, vec = Matrix(GF(2), M), vector(GF(2), vec)
	key = M.solve_right(vec)
	key = long_to_bytes(int(''.join(list(map(str, [bit for bit in key]))), 2))
	print('got key!')
	return key


def recover_key_and_flag():
	key1 = recover_key_from_prime(p)
	key2 = recover_key_from_prime(q)
	for key in (key1, key2):
		try:
			cipher = AES.new(key, AES.MODE_CBC, IV=iv)
			flag = unpad(cipher.decrypt(enc), 16)
			print(flag)
		except:
			pass
	
t = time()
get_params()
d0 = recover_dp_MSBs(12)
print(f'Recovered in {time() - t} seconds')
p, q = factor_n_with_dpmsbs(14, 12)
recover_key_and_flag()
```
`corctf{4nd_a_l1ttl3_bit_0f_gr3en_0ni0ns_on_t0p_dcca3160ef8135ea}`

Thanks to players for trying this challenge!