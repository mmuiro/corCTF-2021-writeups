----
title: corCTF 2021 - leave_it_to_chance
date: Aug 22 2021
author: qopruzjf
tags: crypto
---

Note: This is the challenge author's writeup. It describes the intended solution; however, keep in mind there are likely unintendeds usable to solve as well.

# Challenge

> Do you believe in the heart of the cards?
>
> nc crypto.be.ax 6002

# Solution

We are provided the source file `source.py`, so let's take a look at that first:

```python
from Crypto.Util.number import getPrime
from random import randrange, shuffle
from private import flag

class Game():
	KEY_LEN = 32

	def __init__(self):
		self.p = getPrime(256)
		while self.p % 4 == 3:
			self.p = getPrime(256)
		x = randrange(self.p)
		while pow(x, (self.p-1)//2, self.p) == 1:
			x = randrange(self.p)
		self.a = pow(x, (self.p-1)//4, self.p)
		self.privgen()
		self.signed = []

	def privgen(self):
		self.priv = [randrange(self.p) for _ in range(self.KEY_LEN)]

	def sign(self, m):
		s = 0
		for i in range(len(self.priv)):
			s += (pow(m, i, self.p) * self.priv[i]) % self.p
		return s

	def verify(self, m, s):
		c = self.sign(m)
		return c**4 % self.p == s

def getSig():
	m = int(input("Enter the message you would like to sign, in hex> "), 16) % game.p
	if m not in game.signed:
		s = game.sign(m)
		game.signed.append(m)
		print(f"Signature: {hex(s**4 % game.p)[2:]}")
		hints = [-s % game.p, s*game.a % game.p, -s*game.a % game.p]
		shuffle(hints)
		guess = int(input("Enter a guess for s, in hex> "), 16)
		if guess in hints:
			hints.remove(guess)
		print(f"Hints: {hints[0]} {hints[1]}")
	else:
		print("You already signed that.")

def verifyPair():
	m = int(input("Enter m, in hex> "), 16)
	s = int(input("Enter s, in hex> "), 16)
	if game.verify(m, s):
		print("Valid signature.")
	else:
		print("Invalid signature.")

def guessPriv():
	inp = input("Enter the private key as a list of space-separated numbers> ")
	guess = [int(n) for n in inp.split(" ")]
	if guess == game.priv:
		print(f"Nice. Here's the flag: {flag}")
	else:
		print("No, that's wrong.")
	exit()

def menu():
	print("Enter your choice:")
	print("[1] Get a signature")
	print("[2] Verify a message")
	print("[3] Guess the private key")
	print("[4] Exit")
	options = [getSig, verifyPair, guessPriv, exit]
	choice = int(input("Choice> "))
	if choice - 1 in range(len(options)):
		options[choice - 1]()
	else:
		print("Please enter a valid choice.")

game = Game()
welcome = f"""Welcome.
I will let you sign as many messages as you want.
If you can guess the private key, the flag is yours.
But you only have one chance. Make it count.
p = {game.p}
"""
print(welcome)
while True:
	menu()
```

The private key that we want to guess is a series of 32 numbers, and we're giving any number of chances to sign unique messages(as long as the connection does not break). Since the private key is used as the coefficients of a polynomial `f(x)` used in the signing of messages, we can put the end goal of the challenge as recovering `f(x)`. Based on this, it seems like this challenge may be some variant of [secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

However, we are not directly given the result of `f(m)` for each `m` that we sign; instead, we are given `f(m)^4`. So, it seems like we can't directly apply lagrange interpolation on our `(m, sig)` pairs that we get from the server. Then, let's turn our attention to recovering `s`s from the `sig`s that we get from the server.

## Hint system

Whenever we sign a message, we are given two hints. The `hints` array is initially contains the 3 numbers that are not `s`, but are valid values such that each raised to the 4th power also gives `sig`. To see this, consider:

```python
(-s)^4 = s^4 % p
(s * x^((p-1)/4))^4 = s^4 * x^(p-1) = s^4 % p
(s * (-x)^((p-1)/4))^4 = s^4 * x^(p-1) = s^4 % p
```
In short, they are the other roots of `x^4 = sig % p`. While we can calculate these 4 roots in sage easily, we don't know which one is correct.
Let's look at the hints that we are given. If we send one of the roots `guess` to the server after signing, there are two scenarios:

1. `guess` = `s`. In this scenario, no hints are removed, and we receive 2 roots which are wrong as hints. We're still left with 2 roots, unsure of which is correct.

2. `guess` != `s`. In this scenario, our guess is removed from `hints`, and like in scenario one, we receive 2 roots that are wrong, but we are still left with 2, unsure of which is correct.

It seems like in either scenario, we're still left with 2 options to choose from. So it looks like we have a 50-50 scenario for getting each `s` value correct after receiving hints. Since we need our collection of 32 `(m, s)` pairs to be correct, even if we sign many messages and get `50%` accurate, `50%` inaccurate, to get the right `f(x)` recovered, it's a `(1/2)^32` chance... and since we only have 1 chance per connection, it doesn't feel like this is a valid approach, even with spamming connections.

I mentioned that since 2 options are eliminated, it seems like we have a 50-50 to get each `s` value correct. However, there is something peculiar about the hint system. If we are given 2 options that are wrong, why not give them before sending a `guess`? In the first place, why take a `guess` from the user? To put what the hint system does into words, for the `guess` that you give, it reveals two roots that are wrong **that are not `guess`**, in either of the previously mentioned scenarios. To see why this matters, consider:

Before sending a `guess`, any of the 4 roots has a `1/4` chance of being `s`. So let's select one as `guess`. Then, let's split the 4 roots into 2 groups: 1 group that is just `guess`, and another group that consists of the remaining roots. Then, there is a `1/4` chance that `s` is in group 1, and a `3/4` chance that `s` is in group 2.

After we send `guess`, we receive two roots that are wrong as hints. Here is the important part - both of these roots will **always be part of group 2, since the server never tells you if `guess` was wrong or right**. However, the probability of `s` being in group 1 hasn't changed, nor has it changed for being in group 2. In other words, the single root left over in group 2 now has a `3/4` chance of being correct. So, we can guess the actual value of `s` by selecting the root not in `guess, hint1, hint2` with `3/4` chance. This is a very slight variation of what's known as the Monty-Hall problem, with 4 doors(roots) instead of 3. You can read more about it [here](https://en.wikipedia.org/wiki/Monty_Hall_problem).

So, we now have a method to increase the probability that our `s` works. However, taking a sample of 32 and hoping that all `(m, s)` pairs are correct has probability `(3/4)^32`, which is still quite low... perhaps doable by spamming the server, but there is a more elegant way. (Also, I originally intend to add PoW to this challenge, but I forgot to tell our infra people before starting. This would discourage this solution method.) This involves using error correcting codes. The increase of probability from `50%` to `75%` will actually make a major difference in this, as we will see.

## Berlekamp-Welch Details

The error correcting code technique of interest is known as the Berlekamp-Welch algorithm for Reed Solomon codes. Relevant reading is [here](https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Welch_algorithm), but I will try to explain it more(?) clearly here, if the reader is interested.

Suppose that you have some polynomial `f(x)` of degree `n-1` which you wish to find. Normally, `n` pairs of `(m, s)` is enough to recover `f(x)`(with unique `m` values, of course). However, suppose next that you know that up to `k` of your `s`s are inaccurate. If you know which `(m, s)` pairs are affected, then you only need to collect a total of `n + k` pairs, since you can then simply select the `n` non-affected pairs to reconstruct `f(x)`. However, what if we don't know which ones are affected, but still want to recover `f(x)` with certainty?

The Berlekamp-Welch algorithm allows you to do it as long as you receive `n + 2k` pairs, with up to `k` unknown errors. The idea is based on using an error locating polynomial, which we will call `E(x)`. This is a polynomial of the form `(x - e_1)(x - e_2)...(x - e_k)`, where `e_i` are the `m` values for which `s` is not correct. So, we can see that `E(x)` has degree `k`, and its leading coefficient is `1`.

Then, the key observation is as follows: for all of the `n + 2k` pairs `(m_i, s_i)`, the following equation holds:

`f(m_i) * E(m_i) = s_i * E(m_i)`. Naturally, this is true `mod p` as well.

Let's break down what this means. 
- First, consider the case where `(m_i, s_i)` is a correct pair. Then `f(m_i) = s_i`, so we have `s_i * E(m_i) = s_i * E(m_i)`. Simple enough.
- Next, consider the case where `(m_i, s_i)` is not a correct pair. Then `m_i = e_j` for some `j`; that is, `E(m_i) = 0`, since one of `(x - e_1), (x - e_2), ..., (x - e_k)` will evaluate to `0`. Then, we have `f(m_i) * 0 = s_i * 0`, or `0 = 0`.
So, this equation is satisfied for all pairs. 

Now, let's consider the polynomial `Q(x) = f(x) * E(x)`, from the left side of the above equation. We have already mentioned that `f(x)` is a degree `n-1` polynomial, and `E(x)` is a degree `k` polynomial. Then, `Q(x)` has degree `n - 1 + k`. We note that `Q(x)` has `n + k` unknown coefficients `a_j` then, since with only our `(m_i, s_i)` pairs, we don't know `f(x)` or `E(x)`. 

Then, consider the other side, `s_i * E(x)`. `E(x)` is a polynomial of degree `k`, but only has `k` unknown coefficients `b_j`, as we know the leading coefficient is `1`. Since all `s_i` are known, we are left with a total of `n + 2k` unknowns. 

So, with `n + 2k` pairs, we can construct a system of `n + 2k` equations linear in the `n + 2k` unknowns, and solve for both the coefficients of `Q(x)` and `E(x)`. Constructing the system of equations just has each equation look like:

`a_{n+k-1} * (m_i)^(n+k-1) + a_{n+k-2} * (m_i)^(n+k-2) + .... + a_0 = s_i * ((m_i)^k + b_{k-1}^(k+1) + ... + b_0)`

where your `a` and `b` values are the unknowns. Finding `f(x)` is then simply taking `Q(x)/E(x)`.

Note that this method still works even if there are not exactly `k` errors; as long as the number of errors does not exceed `k`, this method will work. My intuition for this is that the previously mentioned equation at the center of this algorithm still holds even for less than `k` errors, and we can still treat `E(x)` as a `k` degree polynomial by treating some of the correct pairs as erroneous ones.

## Application to this Challenge

We now have a method to recover the original polynomial if we have up to certain number of errors. In our case, `n = 32`. However, `k` varies with the number of samples we send; if we don't use the swapping method to get `s` right with `75%` chance mentioned like before, then, if we call `c` our sample count, then `k` is about `c/2`. Then, we have the following equation:

`32 + 2(c/2) = c`

which has no solutions. What we are observing is that a `50%` error rate is the limit for what Berlekamp-Welch cannot handle. Of course, since `k` is only approximately `c/2`, this is not guaranteed; but the closer `k` is to `c/2`, the more samples you will need to collect; and the more samples you collect, the closer `k` goes to `c/2`. So, unless you get quite lucky, you should not bet on the `50%` chance working out. On the other hand, with a `75%` success rate(and hence `25%` error rate):

`32 + 2(c/4) = c`, which solves to `c = 64`, a very feasibly collectable amount of `(m, s)` pairs.

Here is my implementation of the attack. I used `80` pairs for a bit of leeway.
```python
import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

host, port = 'crypto.be.ax', 6001
r = remote(host, port)
r.recvuntil(b"p = ")
p = Integer(r.recvline())
F = GF(p)
R.<x> = PolynomialRing(F, 'x')

def get_points(n):
	points = []
	for i in range(n):
		r.recvuntil(b"Choice> ")
		r.sendline(b"1")
		r.recvuntil(b"sign, in hex> ")
		r.sendline(hex(i)[2:].encode())
		r.recvuntil(b"Signature: ")
		sig = Integer(int(r.recvline(), 16))
		poly = x^4 - sig
		cands = [int(pair[0]) for pair in poly.roots()]
		r.recvuntil(b"guess for s, in hex> ")
		r.sendline(hex(cands[0])[2:].encode())
		r.recvuntil(b"Hints: ")
		line = r.recvline().decode().split(" ")
		a, b = int(line[0]), int(line[1])
		cands.pop(0)
		cands.remove(a)
		cands.remove(b)
		points.append((i, Integer(cands[0])))
	return points

def get_matrix_and_b(n, k, points):
	M, b = [], []
	dQ = n + k - 1
	for point in points:
		r = []
		for j in range(dQ + 1):
			r.append(F(point[0])^j)
		for j in range(k):
			r.append(-F(point[1]) * F(point[0])^j)
		M.append(r)
		b.append(point[1] * F(point[0])^k)
	M = Matrix(F, M)
	b = vector(F, b)
	return M, b

def get_privkey(a, n, k):
	Q = a[0]
	for i in range(1, n + k):
		Q += a[i]*x^i
	E = a[n + k]
	for i in range(1, k):
		E += a[n + k + i]*x^i
	E += x^k
	P = Q / E
	return P.numerator().list()

def getflag(pay):
	r.recvuntil(b"Choice> ")
	r.sendline(b"3")
	r.recvuntil(b"numbers> ")
	r.sendline(pay.encode())
	r.interactive()

points = get_points(80)
n, k = 32, len(points) // 4
M, b = get_matrix_and_b(n, k, points)
a = M.solve_right(b)
priv = get_privkey(a, n, k)
pay = ' '.join([str(v) for v in priv])
getflag(pay)
```
`corctf{wh0_n3eds_gue551ng_wh3n_y0u_have_l1ne4r_al6ebr4_526d95eadb9686bb}`

Thanks to players who tried this challenge!