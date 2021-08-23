----
title: corCTF 2021 - dividing_secrets
date: Aug 23 2021
author: qopruzjf
tags: crypto
---

Note: This is the challenge author's writeup. It describes the intended solution; however, keep in mind there are likely unintendeds usable to solve as well.

# Challenge

> I won't give you the secret. But, I'll let you divide it.
>
> nc crypto.be.ax 6000

# Solution

Let's take a look at the provided `server.py`.

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from random import randrange
from secret import flag

LIMIT = 64

def gen():
	p = getStrongPrime(512)
	g = randrange(1, p)
	return g, p

def main():
	g, p = gen()
	print("g:", str(g))
	print("p:", str(p))
	x = bytes_to_long(flag)
	enc = pow(g, x, p)
	print("encrypted flag:", str(enc))
	ctr = 0
	while ctr < LIMIT:
		try:
			div = int(input("give me a number> "))
			print(pow(g, x // div, p))
			ctr += 1
		except:
			print("whoops..")
			return
	print("no more tries left... bye")

main()	
```
We are given 64 queries where we can send to the server `div`, and the server will give us `g^(flag // div) mod p`. We want to somehow leak the flag. I started off by considering how we can leak the last bit of `(flag // div)`, as if we can do that, we have a bit-by-bit leak to retrieve the flag by simply dividing by increasing powers of 2(same as pythons' >> operation).

My idea for the leak relies on finding the Legendre Symbol for a number, which you can read about [here](https://en.wikipedia.org/wiki/Legendre_symbol). I will use the notation `(a | b)` to refer to this. In particular, under certain conditions, we can find the legendre symbol `((g^(flag // div)) |  p)` and use it to deduce the last bit of `(flag // div)`. First, let's start with the assumption that `g` is not a quadratic residue, i.e. `(g | p) = -1`. Then, if we write `k = (flag // div)`, consider the following cases:

- If `k` is odd, then the legendre symbol `((g^k) | p)`, calculated by Euler's criterion, is `(g^k)^((p-1)/2) = (g^((p-1)/2))^k = (-1)^k = -1 mod p`. So, `g^k` will not be a quadratic residue either.

- If `k` is even, then we have `(g^k)^((p-1)/2) = (g^((p-1)/2))^k = (-1)^k = 1 mod p`. So, it will be a quadratic residue.

So, we can calculate the legendre symbol `((g^(flag // div)) | p)` to leak the last bit of `(flag // div)`. And as previously described, by sending `div` as increasing powers of 2, we can leak the bits of the flag until `corctf` appears in the bytes. Note that the 64 query limit is a bait and does not actually matter for this method(and likely some other ones), as the flag is invariable across the connections. We can just reconnect until we get `g` that is not a quadratic residue `mod p`, then leak 64 bits, and repeat.

Here is my implementation of the attack:
```python
from pwn import *
from Crypto.Util.number import long_to_bytes

LIMIT = 64
host, port = 'crypto.be.ax' , 6000

def get_params(r):
	r.recvuntil(b'g: ')
	g = int(r.recvline())
	r.recvuntil(b'p: ')
	p = int(r.recvline())
	return g, p

div = 1
flag_bits = ''
while True:
	r = remote(host, port)
	g, p = get_params(r)
	while pow(g, (p-1) // 2, p) == 1:
		r.close()
		r = remote(host, port)
		g, p = get_params(r)
	for _ in range(LIMIT):
		r.recvuntil(b'give me a number> ')
		r.sendline(str(div).encode())
		res = int(r.recvline())
		if pow(res, (p-1) // 2, p) == 1:
			flag_bits = '0' + flag_bits
		else:
			flag_bits = '1' + flag_bits
		div *= 2
		cur = long_to_bytes(int(flag_bits, 2))
		if b'corctf' in cur:
			print(cur)
			r.close()
			exit()
	r.close()
```
`corctf{qu4drat1c_r3s1due_0r_n0t_1s_7h3_qu3st1on8852042051e57492}`

Thanks to players for trying out this challenge!