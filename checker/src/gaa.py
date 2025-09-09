# from math import isqrt
from gmpy2 import isqrt, is_square, is_even, next_prime, mpz, random_state, mpz_urandomb

def quadraticFormula(a: int, b: int, c: int) -> list[int]:
	Dsq = b**2 - 4*a*c
	if Dsq < 0 or not is_square(Dsq):
		return []
	D = isqrt(Dsq)
	r0 = -b + D
	r1 = -b - D
	return [r // (2 * a) for r in (r0, r1) if is_even(r)] # Technically only correct for a = 1 but don't care

# Adapted from crypto-attacks gaa.py
def factor(N: int, rp: int, rq: int):
	global ctr
	global fuck
	i = isqrt(rp * rq)
	initiali = i
	N = mpz(N)
	while True:
		sigma = (isqrt(N) - i)**2
		z = (N - (rp * rq)) % sigma
		roots = quadraticFormula(1, -z, sigma * rp * rq)
		for root in roots:
			if root % rp == 0:
				p = root // rp + rq
				if N % p == 0:
					# print(f'{i - initiali = }')
					ctr += i - initiali
					return p, N // p
			if root % rq == 0:
				p = root // rq + rp
				if N % p == 0:
					# print(f'{i - initiali = }')
					ctr += i - initiali
					return p, N // p
		i += 1 
		if i - initiali > 100_000: # edge case which is only supposed to be hit ~0.003% of the time or so
			fuck += 1
			return 1, 1

initialLeaked = 3
# initialLeaked = 4
# initialLeaked = 5
randstate = random_state(0x69420)
def genSample(bits: int) -> tuple[mpz, mpz, mpz]:
	zerobitmodulus = (1 << initialLeaked)
	leakModulus = (1 << (initialLeaked * 4)) - 1
	bitsPerPrime = bits >> 1
	p = mpz_urandomb(randstate, bitsPerPrime >> 2)
	p -= p % zerobitmodulus
	q = mpz_urandomb(randstate, bitsPerPrime >> 2)
	q -= q % zerobitmodulus
	p = next_prime(p**4)
	q = next_prime(q**4)
	return p * q, p & leakModulus, q & leakModulus

if __name__ == '__main__':
	p = 0x21db9e142a8cbc867cc844621903bfd45a2ba6c0cab17330489bb8c81bd6c6f63508b753d8938b309ecae371016287bfb8298ec6a087315b50e00c58510061
	q = 0x193f4ce31deebab5a9e2b53e9e957b85644f293581cf2af0ebe21e89e495b6eae5efc481a116b9286ef835fcf4beed4444238d167284508b25317cc4b6f91247
	rp = 0x61
	rq = 0x247
	n = 0x356d1a71bbed355e1363ed6c6ef50244c72b5bde5dd6622640c43c1ae1d6d802eeb09527a5f4098fe8cc97732c396203a0b4372b52db119ba8fd58192208d4462ccf606fdcef8900622b43ca98bc7bf24832876973f7fc3b492f144b3134cdbd707bf77a7192606aeab278cb1f20ac92b0b455fa3ed83a7bec4f484d6ece7

	guessedP, guessedQ = factor(n, rp, rq)
	assert guessedP * guessedQ == n
	assert guessedP != 1 and guessedP != n
	print(f'{ctr = }')
	ctr -= ctr

	from tqdm import trange
	from time import time

	bits = 1024
	iters = 3 * 10**3
	totalTime = 0
	for it in trange(iters):
		n, rp, rq = genSample(bits)
		last = ctr
		delta = time()
		guessedP, guessedQ = factor(n, rp, rq)
		delta = time() - delta
		totalTime += delta
		# assert guessedP * guessedQ == n
		# assert guessedP != 1 and guessedP != n
		print(f'{ctr - last = } | {ctr / (it + 1) = }| {fuck / (it + 1) = }, {totalTime / (it + 1) = }')
	print(f'{ctr / iters = }| {fuck / iters = }, {totalTime / iters = }')
