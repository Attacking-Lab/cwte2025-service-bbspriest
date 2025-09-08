from hashlib import sha256, sha3_256
from crypto import Point, sign, verify, G, O, decrypt
from typing import Optional
from pymongo import MongoClient
from os import getenv
from random import randrange

client = MongoClient(f'mongodb://{getenv("DB_USER", "mongo")}:{getenv("DB_PASS", "securepassword123")}@{getenv("DB_HOST", "mongo")}:27017')
print(f'{client = }')
db = client['sins']
sigs = db['sigs']
keys = db['keys']

def insert(sin: bytes, sinId: bytes, unforgiveable: bool):
	obj = {'_id': sinId, 'sin': sin, 'unforgiveable': unforgiveable}
	sigs.update_one({'_id': obj['_id']}, {'$set': obj}, upsert = True)

def get(sinId: bytes) -> Optional[tuple[bytes, bool]]:
	sig = sigs.find_one({'_id': sinId})
	if sig is None:
		return None
	return sig['sin'], sig['unforgiveable']

class Confession:
	def __init__(self, content: bytes, unforgiveable: bool = False):
		assert len(content) <= 200
		if unforgiveable:
			self.sinId = sha3_256(content).hexdigest().encode()
		else:
			self.sinId = sha256(content).hexdigest().encode()
		self.content = content
		self.unforgivable = unforgiveable
	
	@classmethod
	def getConfession(cls, sinId: bytes):
		ret = get(sinId)
		if ret is None:
			raise RuntimeError('Nonexistant sin')
		return cls(*ret)

	def checkConfession(self, pubkey: Point, sig: tuple[int, int]) -> bool:
		assert not self.unforgivable
		return verify(self.content, pubkey, sig)

	def putConfession(self):
		sig = sign(self.content)
		insert(self.content, self.sinId, self.unforgivable)

		return sig

	def putUnforgivableConfession(self):
		insert(self.content, self.sinId, self.unforgivable)
		decryptionKey = randrange(2**63)
		obj = {'_id': self.sinId, 'decryptionKey': decryptionKey}
		keys.update_one({'_id': obj['_id']}, {'$set': obj}, upsert = True)

		return decryptionKey
	
	def decryptConfession(self, decryptionKey: int) -> Optional[bytes]:
		key = keys.find_one({'_id': self.sinId})

		if not key or decryptionKey != key['decryptionKey']:
			return None

		return decrypt(self.content)
