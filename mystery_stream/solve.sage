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

'''
We recover the taps from the polynomial as x^64 + x^61 + x^60 + x^59 + x^58 + x^57 + x^56 + x^54 + x^52 + x^50 + x^49 + x^47 + x^45 + x^35 + x^34 + x^33 + x^32 + x^30 + x^27 + x^25 + x^24 + x^19 + x^17 + x^13 + x^12 + x^10 + x^7 + x^5 + x^4 + x^2 + 1.

This is then factorable into the following 4 polynomials:
p8 = x^8 + x^6 + x^5 + x^4 + 1
p14 = x^14 + x^13 + x^12 + x^2 + 1
p19 = x^19 + x^18 + x^17 + x^14 + 1
p23 = x^23 + x^18 + 1

LFSRs with each of these polynomials on their own would generate output streams of periods 255, 16383, 524287, and 8388607 respectfully.
Now, we note that the connection of this challenge to LFSR suggests that poly in pub.sage is the LFSR's polynomial above(apologies if this felt guessy).
Based on this, and the information from pub.sage indicating key is periodic, with the matrix M modeling clocking the LFSR's internal state, we have candidate values for [REDACTED] in M^[REDACTED], i.e. the period of the key. They are the LCMs of combinations of the above periods. Details here: https://math.stackexchange.com/questions/872984/sequences-length-for-lfsr-when-polynomial-is-reducible\
Considering that large periods don't seem to be viable for bruteforcing the key or doing frequency analysis, the most likely period length is 255, which is the one I chose. So, we can try frequency analysis to decrypt.
'''
g256_crack(ct, 255, delim, 'finish')