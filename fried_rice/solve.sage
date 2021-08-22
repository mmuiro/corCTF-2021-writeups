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
