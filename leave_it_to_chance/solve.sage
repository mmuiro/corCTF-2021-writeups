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


