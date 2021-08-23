----
title: corCTF 2021 - mystery_stream
date: Aug 22 2021
author: qopruzjf
tags: crypto
---

Note: This is the challenge author's writeup. It describes the intended solution; however, keep in mind there are likely unintendeds usable to solve as well.

# Challenge

> Mysterious stream cipher. Wonder what the seed was...

# Solution

We are provided two source files and a ciphertext file `ct`. Let's take a look at `source.py` first:

```python
from random import randrange
from secrets import flag, key
from Crypto.Util.number import long_to_bytes

def bsum(state, taps, l):
	ret = 0
	for i in taps:
		ret ^= (state >> (l - i))
	return ret & 1

class Gen:
	def __init__(self, key, slength):
		self.state = key
		self.slength = slength
		self.TAPS = [2, 4, 5, 7, 10, 12, 13, 17, 19, 24, 25, 27, 30, 32, 
		33, 34, 35, 45, 47, 49, 50, 52, 54, 56, 57, 58, 59, 60, 61, 64]

	def clock(self):
		out = bsum(self.state, self.TAPS, self.slength)
		self.state = (out << (self.slength - 1)) + (self.state >> 1)
		return out

def insertflag(fn, flag):
	txt = b''
	with open(fn, 'rb') as f:
		txt = f.read()
	i = randrange(0, len(txt))
	txt = txt[:i] + flag + txt[i:]
	with open(fn, 'wb') as f:
		f.write(txt)

def gf256_multiply(a,b):
  p = 0
  for _ in range(8):
    if b % 2:
      p ^= a
    check = a & 0x80
    a <<= 1
    if check == 0x80:
      a ^= 0x1b
    b >>= 1
  return p % 256

def encrypt(fn, outf, cipher):
	pt = b''
	with open(fn, 'rb') as f:
		pt = f.read()
	ct = b''
	for byte in pt:
		genbyte = 0
		for i in range(8):
			genbyte = genbyte << 1
			genbyte += cipher.clock()
		ct += long_to_bytes(gf256_multiply(genbyte, byte))
	with open(outf, 'wb') as f:
		f.write(ct)

insertflag('pt', flag)
cipher = Gen(key, 64)
encrypt('pt', 'ct', cipher)
```

Looking at this, we can see that `Gen` is supposed to behave as a linear-feedback-stream-cipher, or LFSR for short. In encrypting the plaintext with the cipher, first, the flag is inserted into a random position, and then bytes are generates from the LFSR, which are multiplied byte-by-byte with the plaintext bytes via the `gf256_multiply` method.

To get a clearer view on the method of attack for this challenge, let's also take a look at the `pub.sage` file:

```python
R.<x> = PolynomialRing(GF(2), 'x')
poly = [REDACTED]
assert poly.degree() == 64
M = [poly.list()[1:]]
for i in range(63):
	M.append([1 if j == i else 0 for j in range(64)])
M = Matrix(GF(2), M)
A = M^[REDACTED]
E, S = A.eigenspaces_right(format='galois')[0]
assert E == 1
keyvec = S.random_element()
key = int(''.join([str(d) for d in keyvec]), 2)
print(key)
```

Analyzing the source from bottom up, it seems that the `key` used in `source.py` is periodic in some fashion, with period `a = [REDACTED]`. This comes from `key` being in the eigenspace of `M^a` for eigenvalue 1, meaning `(M^a) * keyvec = keyvec`. The question then is what `M` represents, and what the redacted `a` value is, and how they will help us solve the challenge.

Looking at the `M` matrix's construction, we can see that it is comprised of the first row being the unknown `poly`'s coefficients, while the remaining rows seem to follow an identity matrix. The structure is something like this:

```
[[ ---- poly coefficients ---- ]
[1 0 0 0 0 0 0 0 0 0 0 0 .... 0]
[0 1 0 0 0 0 0 0 0 0 0 0 .... 0]
[0 0 1 0 0 0 0 0 0 0 0 0 .... 0]
.
.
.
[0 0 0 0 0 0 0 0 0 0 .... 0 1 0]]
```

If we replace the first row with all `0`s, then you may recognize that this is a lower shift matrix, which, when multiplied by a vector, will move all the entries in that vector down one. To see why this matters, let's take a look at `Gen` from `source.py` once again:

```python
def bsum(state, taps, l):
	ret = 0
	for i in taps:
		ret ^= (state >> (l - i))
	return ret & 1

class Gen:
	def __init__(self, key, slength):
		self.state = key
		self.slength = slength
		self.TAPS = [2, 4, 5, 7, 10, 12, 13, 17, 19, 24, 25, 27, 30, 32, 
		33, 34, 35, 45, 47, 49, 50, 52, 54, 56, 57, 58, 59, 60, 61, 64]

	def clock(self):
		out = bsum(self.state, self.TAPS, self.slength)
		self.state = (out << (self.slength - 1)) + (self.state >> 1)
		return out
```

Specifically, let's take a look at the `clock` function. With each call to the `clock` function, the last bit of the state is removed by `(self.state >> 1)`, and the `out` bit is put at the top by `(out << (self.slength - 1))`. The out bit is simply the bitwise sum(XOR) of the bits of `self.state` at the positions in `self.TAPS`. This may seem rather familiar, now that we've taken a look at `M`, calling `clock` seems to modify `self.state` very similarly to applying `M` to `keyvec`, where `keyvec` is simply the bitvector representation of `key`.

Here, we make one of the key observations of this challenge: it is likely that the first row of `M`, the coefficients of `poly`, are actually just the bit positions in `taps`. This inference is made both upon the previous observations, and upon the fact that LFSRs each have their own characteristic polynomial which define their taps(and vice versa), which you can read more about [here](https://en.wikipedia.org/wiki/Linear-feedback_shift_register). This means that we can reasonably conclude that the `poly` from `pub.sage` is the LFSR's characteristic polynomial. (Though, it seems that this part turned out more guessy than intended. Apologies to anybody who may have been frustrated by this. I actually wanted this part to be clear to everyone, but people managed to solve without me just putting it into `pub.sage`. In the end, I just asked for anybody stuck to open a ticket. I'll try to make things clearer next time.)

To recover the polynomial from the taps, you can use the following code, in sagemath:
```python
R.<x> = PolynomialRing(GF(2), 'x')
taps = [2, 4, 5, 7, 10, 12, 13, 17, 19, 24, 25, 27, 30, 32, 33, 34, 35, 45, 47, 49, 50, 52, 54, 56, 57, 58, 59, 60, 61, 64]
poly = 1
for exp in taps:
	poly += x^exp
```
to get `x^64 + x^61 + x^60 + x^59 + x^58 + x^57 + x^56 + x^54 + x^52 + x^50 + x^49 + x^47 + x^45 + x^35 + x^34 + x^33 + x^32 + x^30 + x^27 + x^25 + x^24 + x^19 + x^17 + x^13 + x^12 + x^10 + x^7 + x^5 + x^4 + x^2 + 1` as the LFSR polynomial. Again, you can read the linked wikipedia page to see the relationship between the taps and the polynomial.

Based on this assumption, we can now recognize that the matrix `M` essentially models applying `clock` to change the internal state of the LFSR. With this information, from our observation that `keyvec` is periodic in being multiplied by `M`, it's likely that the issue in the challenge is that `key` is periodic, with a period shorter than optimal(in this case, `2^64 - 1`) to allow for some attack. The ciphertext `ct` being rather long also hints towards this.

Then, the next target is to find what the possible values of `a` are. This is where the main idea of the challenge lies - if we work under the assumption that the period of the LFSR is shorter than optimal, then its taps, and thus its polynomial, are likely not optimal. Since irreducibility of the characteristic polynomial is what gives an LFSR the optimal period length, it means that `poly` in this case is likely not irreducible. And in fact, factoring `poly` in sagemath gives us the following 4 factors:
```python
p8 = x^8 + x^6 + x^5 + x^4 + 1
p14 = x^14 + x^13 + x^12 + x^2 + 1
p19 = x^19 + x^18 + x^17 + x^14 + 1
p23 = x^23 + x^18 + 1
```
With this, the insight on the possible values of `a` comes from this stackexchange post: [here](https://math.stackexchange.com/questions/872984/sequences-length-for-lfsr-when-polynomial-is-reducible). Please do read more into it if interested.

To sum it up, for a LFSR with reducible characteristic polynomial `poly`, its possible periods(depending on the initial state) will be the least-common-multiples of the periods of the LFSRs with a characteristic polynomial that is an irreducible factor of `poly`. Specifically, in the case of this challenge, the periods of the 4 LFSRs based on the 4 factors of `poly` are `255`, `16383`, `524287`, and `8388607` respectively. You can obtain these numbers from the aforementioned wikipedia page as well. So, the possible periods of LFSR here are LCMs of combinations of these 4 numbers. With this, we can calculate all candidates for `a`. 

In regards to finding `a` candidates, some people asked me during the CTF if I could provide a bound for `a`. The reason I said no is because the idea was to use this to find candidates for `a`, so hopefully that makes sense.

Now, knowing candidates for `a`, there are 2 main approaches: either bruteforce decrypt through all the keys with period length `a`, or use frequency analysis on the long `ct` to decrypt. Both of these options are really only viable if the period is short enough, so we can start off by testing `a=255`, as there are `255` keys with this period, and having a rather long period length means frequency analysis will likely fail, as `ct` is not long enough. My intended approach was to use the latter.

One thing to note in doing this: the bitstream is of length `255`, but to do frequency analysis, under the assumption that the plaintext is in English(something I couldn't mention directly in the challenge description, as that would give away quite a bit of the solution to experienced players), we want to look at the bytes instead, so that we can have a valid delimiter. We can get past this by simply treating the LFSR's output as a 255 byte GF256 multiplication key, since `8*255` is divisible by `255`.

Here is my script to do so:

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
delim = bytes_to_long(b' ')

F = GF(2^8, 'x', modulus=x^8 + x^4 + x^3 + x + 1)

def div(a, b):
	elem = F.fetch_int(a) / F.fetch_int(b)
	return elem.integer_representation()

def g256_decrypt(m: bytes, key: list, outf):
	ct = b''
	for i in range(len(m)):
		ct += long_to_bytes(div(m[i], key[i % len(key)]))
	with open(outf, 'wb') as f:
		f.write(ct)

def g256_crack(ct: bytes, keylen: int, delim: int, outf):
	key = ['']*keylen
	for i in range(keylen):
		index = i
		samples = {}
		while index < len(ct):
			cur = ct[index]
			if cur not in samples:
				samples[cur] = 0
			samples[cur] += 1
			index += keylen
		maxfreqbyte = max(samples, key=samples.get)
		key[i] = div(maxfreqbyte, delim)
	g256_decrypt(ct, key, outf)
	print("done")

ct = b''
with open('ct', 'rb') as f:
	ct = f.read()

g256_crack(ct, 255, delim, 'finish')
```
You can view this in `solve.sage` as well. Then, simply searching for the prefix `corctf{` will give us the flag:
`corctf{p3ri0dic4lly_l00ping_on_4nd_on...}`

As another note, the reason I used `gf256_multiply` rather than something simpler like XOR was to avoid solves by simply applying `xortool` without much thought, so at the very least, teams would have to understand the approach they're using.

Thanks to all the players for trying out this challenge!