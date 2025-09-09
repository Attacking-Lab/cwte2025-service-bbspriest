BBS Priest
================


Authors:
* dagurb (Dagur Benjamínsson)

Categories:
* crypto

    <!--
    Topics typically correspond to the vulnerabilities of each flag store, e.g.,
    web, pwn, rev, crypto, etc. You are encouraged to implement different topics on
    each service, for instance by combining Web vulnerabilities with binary
    exploitation, or cryptography and reversing, and so on
    
    
    Directory structure overview:
    
    service-related files go into: /service
    checker-related files go into /checker
    
    
    When the vulnbox image is built, the contents of /service is copied.
    To prevent e.g. leaking source code, please use a docker-compose.override.yml symlink to enable debug features.
    -->

Overview
--------

    <!--
    Include an exhaustive overview of the service and its intended functionalities.
    Explain in detail the technological stack that you plan to adopt, but do not
    introduce the vulnerabilities yet
    -->

### Flag Store 1

    <!--
    Detail how flags are stored and what do they represent. Explain if you plan to
    use attack info and how
    -->

Flags are stored as (normal) confessions, protected by a ECDSA signature.

### Flag Store 2

Flags are stored as unforgivable confessions, and are encrypted with RSA.

Vulnerabilities
---------------

    <!--
    Provide a high-level description of the vulnerabilities affecting each flag
    store. Include a proof-of-concept of the exploit, or - if this is not possible -
    a description of the attack flow. For each *vulnerability*, specify the intended
    difficulty level of the exploit, its *discoverability* by inspecting traffic
    dumps, etc., and *patchability*. Accepted values are *easy*, *medium*, *hard*.
    Vulnerabilities that are easy to exploit should be also easy to patch. On the
    other hand, it is fine to require more complex patches if the difficulty is also
    hard. It is also fine to keep the pathcability as easy if the discoverability is
    hard. Concerning discoverability, as a rule of thumb, there are 3 cases: *easy*,
    the exploit can be easily identified and reflected; *medium*, the exploit can be
    easily identified, but reflection is not trivial; *hard*, when identification
    and especially reflection are unlikely to be possible, e.g., if the connection
    is encrypted. We perfectly understand that precisely defining all possible
    vulnerabilities at this stage is difficult, but it's important to incorporate
    them during the design phase instead of adding some vulnerabilities at the end
    of the development
    -->

### Flag Store 1, Vuln 1

    <!--
    Short description of the vuln and how to exploit it
    -->

Signature checking algorithm can be bypassed by using the secret fourth option and providing the identity point as a generator. The signature algorithm checks if $r$ or $s$ are $0$ mod $O$, but it doesn't check if the generator is the identity point.

A convenient way to write this exploit is to pass in $(G.x, hash(sinId))$, but any signature of the form $(G * (sinId * s^-1).x should work, s)$
```python
>>> f = lambda x: int.from_bytes(sha256(x).digest()) % O
>>> assert verify(sinId, Point(0, 0), (G.x, f(b'1')))
```

* Difficulty: easy
* Discoverability: easy
* Patchability: easy
* Categories: crypto

### Flag Store 1, Vuln 2
The private key $k$ can be recovered using an invalid curve attack by sending several points on different curve with non-prime order. That way the attacker can recover partial dlogs and Pohlig-Hellman them together.

* Difficulty: medium [^1]
* Discoverability: medium
* Patchability: easy
* Categories: crypto

[^1]: debating on whether to label this as hard or not, since conceptually, this is very simple, but it is a bit of effort to implement.

### Flag Store 1, Vuln 3
The nonce is generated using
```python
k = int.from_bytes(urandom(30)) % O
```

Which generates a 30 * 8 = 240 bit nonce, but we work over a 256 bit curve. This means that the nonce is biased and we can use a bogstandard ECDSA biased nonce attack. Note that this does require LLL, so the contestants infra must be able to support some way of installing non-trivial binaries/sagemath.

* Difficulty: medium
* Discoverability: medium [^1]
* Patchability: easy
* Categories: crypto

[^1]: For a crypto player, this could be classified as easy, maybe medium since it is not immediately obvious at a glance, but for a non-crypto player, this may be very hard to find (without the help of chatgpt ig?). So I decided to label this as medium.

### Flag Store 1, Vuln 4
We can ask for an unforgivable sin, and pass in a normal sin, since the server doesn't discriminate between normal and unforgivable sins properly enough.

* Difficulty: easy,
* Discoverability: easy (I think?)
* Patchability: easy
* Categories: misc (rev?)

### Flag Store 2, Vuln 1
The init function is seeded with the current time (in seconds). We can guess when the cryptoaccelerator was initialized, both using the uptime provided, and also by knowing that it was started during the CTF, and recover all possible privkeys from there. Note that we might have to cycle though very many keys, so having a global precomputed hashtable would decrease the time complexity by a linear factor.

* Difficulty: medium
* Discoverability: medium (easy to guess, perhaps?)
* Patchability: easy
* Categories: rev

### Flag Store 1, Vuln 2
The cryptoaccelerator generates a prime by calculating `nextprime(random**4)`, and `random` is always guaranteed to have 3 leading zeros (if not, the attack is flaky). Then we essentially have primes of the form $p = a^m + r_p$, $q = b^m + r_p$. This is ofcourse vulnerable to the GAA attack. A commonly available implementation from the `crypto-attacks` library is listed below.

```python
def factorize(N, rp, rq):
	"""
	Recovers the prime factors from a modulus using the Ghafar-Ariffin-Asbullah attack.
	More information: Ghafar AHA. et al., "A New LSB Attack on Special-Structured RSA Primes"
	:param N: the modulus
	:param rp: the value rp
	:param rq: the value rq
	:return: a tuple containing the prime factors
	"""
	i = ceil(sqrt(rp * rq))
	x = ZZ["x"].gen()
	while True:
		sigma = (round(int(sqrt(N))) - i) ** 2
		z = (N - (rp * rq)) % sigma
		f = x ** 2 - z * x + sigma * rp * rq # You could also just use the quadratic formula to calculate this. No need for sagemath
		for x0 in f.roots(multiplicities=False):
			if x0 % rp == 0:
				p = int((x0 // rp) + rq)

				if N % p == 0:
					return p, N // p
			if x0 % rq == 0:
				p = int((x0 // rq) + rp)
				if N % p == 0:
					return p, N // p

		i += 1
```

* Difficulty: medium-hard
* Discoverability: hard
* Patchability: depends (one could just rip the entire cryptoaccelerator out?)
* Categories: crypto + rev

Patches
-------

    <!--
    For each of the vulnerabilities reported in the previous section, outline a
    possible fix, can use diff files here to visualize changes but a text
    explanation is also required)
    -->

### Flag Store 1, Vuln 1
Possible fix:
```diff
def verify(data: bytes, pubkey: Point, sig: tuple[int, int]):
	z = int.from_bytes(sha256(data).digest()) % O
>	assert not pubkey.isIdentity()
```
This checks if the provided generator point is the identity point.

### Flag Store 1, Vuln 2,
Possible fix:
```diff
class Point:
	def __init__(self, x: int, y: int):
		self.x = x
		self.y = y
>		assert self.isOnCurve()
```

This checks if the point is actually on the curve. Notice that this does NOT patch vuln 1, as the identity point is on the curve, even though it does not obey the curve equation.

### Flag Store 1, Vuln 3
Possible fix:
```diff
64c64
< priv = int.from_bytes(urandom(30)) % O
---
> priv = int.from_bytes(urandom(32)) % O
69c69
< 	k = int.from_bytes(urandom(30)) % O
---
> 	k = int.from_bytes(urandom(32)) % O
```

This avoids the nonce bias by sampling a random number greater than $O$. Note that this introduces a very very small modulo bias, so another possible fix would be to use `k = secrets.randbelow(O)`

### Flag Store 1, Vuln 4
Possible fix:
```diff
< def decryptConfession(self, decryptionKey: int) -> Optional[bytes]:
< 	key = keys.find_one({'_id': self.sinId})
< 
< 	if not key or decryptionKey != key['decryptionKey']:
< 		return None

< 	return decrypt(self.content)
---
> def decryptConfession(self, decryptionKey: int) -> Optional[bytes]:
> 	key = keys.find_one({'_id': self.sinId, 'unforgivable': True})
> 
> 	if not key or decryptionKey != key['decryptionKey']:
> 		return None

> 	return decrypt(self.content)
```

We restrict the decryptConfession to only search for unforgivable sins

### Flag Store 2, Vuln 1
Possible fix:
```diff
< cryptoaccelerator.init(int(time.time()))
---
> cryptoaccelerator.init(secrets.randbelow(2**31))
```

Seed the random number generator with a random number. This does open us up to a 2^31 bruteforce, but it has a high constant factor, and each possible seed could be responsible for thousands of keys, making it impractical.

### Flag Store 2, Vuln 2
Either throw the entire cryptoaccelerator in the bin, or patch the mpz_urandomb call to generate a properly sized random value and patch the multiplications with NOPs until mpz_nextprime is reached.

Work Packages
-------------

    <!--
    Brief description of each work package
    -->

### WP 1: Name

#### WP 1.1: Subtask

    <!--
    Short Description
    -->

#### WP 1.N: Subtask

...

### WP N: Name

    <!--
    Short Description
    -->

...
