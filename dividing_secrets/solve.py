from pwn import *
from Crypto.Util.number import long_to_bytes

LIMIT = 64
host, port = '35.208.224.209' , 6000

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
