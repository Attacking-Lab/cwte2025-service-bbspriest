from hashlib import sha256
from os import urandom

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
O = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

class Point:
	def __init__(self, x: int, y: int):
		self.x = x
		self.y = y
	
	def __str__(self):
		return f'({self.x}, {self.y})'

	def __repr__(self):
		return str(self)

	def __eq__(self, other: 'Point'):
		return self.x == other.x and self.y == other.y

	def isOnCurve(self):
		return (self.y ** 2) % p == (self.x ** 3 + a * self.x + b) % p or (self.x == 0 and self.y == 0)

	def isIdentity(self):
		return self.x == 0 and self.y == 0

	def add(self, p2: 'Point') -> 'Point':
		if self.isIdentity():
			return Point(p2.x, p2.y)
		if p2.isIdentity():
			return Point(self.x, self.y)

		try:
			if self.x == p2.x and self.y == p2.y:
				slope = (3 * (self.x ** 2) + a) * pow(2 * self.y, -1, p)
				slope %= p
			else:
				slope = (p2.y - self.y) * pow(p2.x - self.x, -1, p)
				slope %= p
		except ValueError:
			return Point(0, 0)

		x3 = (slope ** 2) - self.x - p2.x
		y3 = slope * (self.x - x3) - self.y

		return Point(x3 % p, y3 % p)

	def mul(self, scalar: int) -> 'Point':
		base = Point(self.x, self.y)
		result = Point(0, 0)
		while scalar != 0:
			if scalar & 1 == 1:
				result = result.add(base)
			base = base.add(base)
			scalar >>= 1

		return result

G = Point(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
assert G.isOnCurve()

def sign(data: bytes): # NOTE: insecure, only here for testing
	z = int.from_bytes(sha256(data).digest()) % O
	# k = int.from_bytes(urandom(O.bit_length() // 8)) % O
	k = int.from_bytes(urandom(30)) % O
	P = G.mul(k)
	r = P.x % O
	s = (pow(k, -1, O) * (z + r * priv)) % O

	return r, s

def signraw(z: int, priv: int) -> tuple[int, int]:
	k = int.from_bytes(urandom(30)) % O
	P = G.mul(k)
	r = P.x % O
	s = (pow(k, -1, O) * (z + r * priv)) % O

	return r, s


def verify(data: bytes, pubkey: Point, sig: tuple[int, int]) -> bool:
	z = int.from_bytes(sha256(data).digest()) % O
	assert not pubkey.isIdentity()
	assert pubkey.isOnCurve()
	assert pubkey.mul(O).isIdentity()
	r, s = sig
	assert r % O != 0 and s % O != 0
	sInv = pow(s, -1, O)
	u1 = (z * sInv) % O
	u2 = (r * sInv) % O

	P = G.mul(u1).add(pubkey.mul(u2))
	if P.x == 0 and P.y == 0:
		return False

	return (r - P.x) % O == 0
