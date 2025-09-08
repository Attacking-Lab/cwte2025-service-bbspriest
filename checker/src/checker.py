from enochecker3.chaindb import ChainDB
from enochecker3.enochecker import Enochecker, AsyncSocket, DependencyInjector
from enochecker3.types import (
	ExploitCheckerTaskMessage,
	GetflagCheckerTaskMessage,
	InternalErrorException,
	MumbleException,
	PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_in

from typing import Optional, cast, Any

from logging import LoggerAdapter
from secrets import randbits
from string import ascii_letters, digits
from hashlib import sha256

from connectionInterface import Session
from crypto import *

from random import Random
from biasednonce import recover_private_key

checker = Enochecker('BBSPriest', 9999)
app = lambda: checker.app # here because it was in fireworx and stldoctor

frequentSins = [
	'I flagshared in an A/D',
	'I upload a RSA chall prime to factordb',
	'I leaked flags in the discord',
	'I don\'t know what mvm means',
	'I abused university clusters to brute',
]


noiseSpace = (ascii_letters + digits).encode()
def noise(nmin: int, nmax: int, random: Random) -> bytes:
	n = random.randint(nmin, nmax)
	# return b''.join(random.choice(noiseSpace) for _ in range(n))
	return bytes(random.choice(noiseSpace) for _ in range(n))

async def getdb(db: ChainDB, key: str) -> tuple[Any, ...]:
    try:
        return await db.get(key)
    except KeyError:
        raise MumbleException(
            "Could not retrieve necessary info for service interaction"
        )

def validatePubkey(rawpubkey: bytes, logger: LoggerAdapter) -> Point:
	pointStrs = rawpubkey[1:-1].split(b', ')
	if len(pointStrs) != 2:
		logger.critical(f'public key is composed of {len(pointStrs)} ints (expected 2)')
		raise MumbleException('Malformed public key')
	if not pointStrs[0].isdigit() and not pointStrs[1].isdigit():
		logger.critical(f'public key has non-string elements')
		raise MumbleException('Malformed public key')
	try:
		pubkey = Point(*map(int, pointStrs))
	except:
		logger.critical('Point construction failed')
		raise MumbleException('Malformed public key')

	if not pubkey.isOnCurve():
		logger.critical('Point is not on curve')
		raise MumbleException('Malformed public key')

	return pubkey

async def getPubkey(client: Session, logger: LoggerAdapter) -> Point:
	await client.recvuntil(b': ')
	rawpubkey = (await client.recvline()).strip()
	pubkey = validatePubkey(rawpubkey, logger)
	return pubkey


async def confessSin(sin: bytes, client: Session, logger: LoggerAdapter):
	# TODO: maybe validate that output is correct in a better manner?
	pubkey = await getPubkey(client, logger)

	try:
		banner = await client.recvuntil(b'> ')
		assert b'555-123' in banner, 'bad banner'

		client.sendline(b'0')
		resp = await client.recvuntil(b'> ')
		assert b'flagshared' in resp, 'bad frequent sin list'

		client.sendline(b'5')
		await client.recvuntil(b'> ')
		client.sendline(sin)

		resp = await client.recvline()
		assert resp.startswith(b'You have been'), resp
		sinIdLine = await client.recvline()
		sinId = sinIdLine.split(b': ')[1].strip(b'\n.')
		absolutionSignatureLine = await client.recvline()
		absolutionSignature = absolutionSignatureLine.split(b': ')[1].strip(b'\n.')
		# Assert that sinId and absolutionSignature give correct signature
	except AssertionError:
		logger.critical('Service behaved wrongly while accepting sin confession')
		raise MumbleException('Failed to confess sin')

	try:
		assert sinId.decode() == sha256(sin).hexdigest()
		r, s = map(int, absolutionSignature.strip(b' ().').split(b', '))
		verify(sinId, pubkey, (r, s))
	except:
		raise MumbleException('Wrong signature')

	return sinId, absolutionSignature

async def retrieveSin(sinId: bytes, sig: bytes, client: Session, logger: LoggerAdapter):
	# TODO: maybe validate that output is correct in a better manner?
	try:
		banner = await client.recvuntil(b'> ')
		assert b'555-123' in banner

		client.sendline(b'2')
		resp = await client.recvuntil(b'> ')
		assert b'particular' in resp

		client.sendline(sinId)
		resp = await client.recvuntil(b'> ')
		assert b'signature' in resp
		client.sendline(sig)

		ret = await client.recvline()
		return ret
	except AssertionError:
		logger.critical('Service behaved wrongly while looking up sin confession')
		raise MumbleException('Failed to retrieve sin')

def customG(random: Random) -> Point:
	while True:
		x = random.randrange(p)
		ySq = (pow(x, 3, p) + a * x + b) % p
		y = pow(ySq, (p + 1) // 4, p) # fails is sqrt doesn't exist
		if pow(y, 2, p) == ySq:
			break
	customG = Point(x, y)
	assert customG.isOnCurve()

	return customG

async def secretFifthOption(sinId: bytes, sig: bytes, client: Session, logger: LoggerAdapter, customG: Optional[Point] = None):
	# TODO: maybe validate that output is correct in a better manner?
	pubkey = await getPubkey(client, logger)
	if customG is None:
		customG = G

	try:
		banner = await client.recvuntil(b'> ')
		assert b'555-123' in banner

		client.sendline(b'5')
		resp = await client.recvuntil(b'> ')
		assert b'generator' in resp

		client.sendline(f'{customG.x}, {customG.y}'.encode())
		resp = await client.recvuntil(b'> ')
		assert b'sin id' in resp

		client.sendline(sinId)
		resp = await client.recvuntil(b'> ')
		assert b'signature' in resp
		client.sendline(sig)

		ret = await client.recvline()
		if customG == G:
			assert b'absolved' in ret
		else:
			assert b'Invalid' in ret or b'absolved' in ret

		return ret
	except AssertionError:
		logger.critical('Service behaved wrongly while looking up sin confession')
		raise MumbleException('Failed to retrieve sin')

async def confessGiven(client: Session, logger: LoggerAdapter, sinIdx: int, pubkey: Point):
	try:
		banner = await client.recvuntil(b'> ')
		assert b'555-123' in banner

		client.sendline(b'0')
		resp = await client.recvuntil(b'> ')
		assert b'flagshared' in resp

		sin = frequentSins[sinIdx].encode()
		client.sendline(str(sinIdx).encode())

		resp = await client.recvline()
		assert resp.startswith(b'You have been'), resp
		sinIdLine = await client.recvline()
		sinId = sinIdLine.split(b': ')[1].strip(b'\n.')
		absolutionSignatureLine = await client.recvline()
		absolutionSignature = absolutionSignatureLine.split(b': ')[1].strip(b'\n.')
	except AssertionError:
		logger.critical('Service behaved wrongly while accepting sin confession')
		raise MumbleException('Failed to confess sin')

	try:
		assert sinId.decode() == sha256(sin).hexdigest()
		r, s = map(int, absolutionSignature.strip(b' ().').split(b', '))
		verify(sinId, pubkey, (r, s))
	except:
		raise MumbleException('Wrong signature')

	return sin, sinId, absolutionSignature

async def confessRandom(client: Session, logger: LoggerAdapter, random: Random, pubkey: Point):
	sinIdx = random.randrange(len(frequentSins))
	return await confessGiven(client, logger, sinIdx, pubkey)

@checker.register_dependency
def _get_session(socket: AsyncSocket, logger: LoggerAdapter) -> Session:
	return Session(socket, logger)
_ = _get_session

# NOTE: Sheißefix, remove when upgrading
"""
@checker.register_dependency
def _get_random() -> Random:
	random = Random()
	random.seed(0x69420)
	return random
_ = _get_random
"""

@checker.putflag(0)
async def putflag0(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, di: DependencyInjector, db: ChainDB) -> str:
	client = cast(Session, await di.get(Session))
	sinId, absolutionSignature = await confessSin(task.flag.encode(), client, logger)
	await db.set('sig', (sinId, absolutionSignature))
	return sinId.decode()

@checker.getflag(0)
async def getflag0(task: GetflagCheckerTaskMessage, logger: LoggerAdapter, di: DependencyInjector) -> None:
	db = await di.get(ChainDB)
	sinId, absolutionSignature = cast(tuple[bytes, bytes], await getdb(db, 'sig'))

	client = await di.get(Session)
	flagString = await retrieveSin(sinId, absolutionSignature, client, logger)

	assert_in(task.flag.encode(), flagString, 'Failed to retrieve flag')

@checker.havoc(0)
async def havocFrequentSin(logger: LoggerAdapter, di: DependencyInjector, random: Random) -> None:
	client = await di.get(Session)
	pubkey = await getPubkey(client, logger)

	_ = await confessRandom(client, logger, random, pubkey)

@checker.havoc(1)
async def havocRandomSin(logger: LoggerAdapter, di: DependencyInjector, random: Random) -> None:
	client = await di.get(Session)

	_ = await confessSin(noise(10, 20, random), client, logger)


@checker.putnoise(0)
async def putnoiseFrequent(logger: LoggerAdapter, di: DependencyInjector, random: Random) -> None:
	db = await di.get(ChainDB)
	client = await di.get(Session)
	pubkey = await getPubkey(client, logger)

	sin, sinId, absolutionSignature = await confessRandom(client, logger, random, pubkey)
	await db.set('sin', (sin, sinId, absolutionSignature))

@checker.getnoise(0)
async def getnoiseFrequent(logger: LoggerAdapter, di: DependencyInjector) -> None:
	db = await di.get(ChainDB)
	sin, sinId, absolutionSignature = cast(tuple[bytes, bytes, bytes], await getdb(db, 'sin'))

	client = await di.get(Session)
	flagString = await retrieveSin(sinId, absolutionSignature, client, logger)

	assert_in(sin, flagString, 'Failed to retrieve noise')

@checker.putnoise(1)
async def putnoiseRandom(logger: LoggerAdapter, di: DependencyInjector, random: Random) -> None:
	db = await di.get(ChainDB)
	client = await di.get(Session)

	sin = noise(10, 20, random)
	sinId, absolutionSignature = await confessSin(sin, client, logger)

	await db.set('sin', (sin, sinId, absolutionSignature))

@checker.getnoise(1)
async def getnoiseRandom(logger: LoggerAdapter, di: DependencyInjector) -> None:
	db = await di.get(ChainDB)
	sin, sinId, absolutionSignature = cast(tuple[bytes, bytes, bytes], await getdb(db, 'sin'))

	client = await di.get(Session)
	flagString = await retrieveSin(sinId, absolutionSignature, client, logger)

	assert_in(sin, flagString, 'Failed to retrieve noise')


@checker.exploit(0)
async def badGenerator(task: ExploitCheckerTaskMessage, di: DependencyInjector, logger: LoggerAdapter):
	searcher = await di.get(FlagSearcher)
	logger = await di.get(LoggerAdapter)
	assert task.attack_info is not None

	client = await di.get(Session)

	sinId = task.attack_info.encode()
	r = G.x
	s = int(sinId, 16) % O
	resp = await secretFifthOption(sinId, f'({r}, {s})'.encode(), client, logger, Point(0, 0))

	if flag := searcher.search_flag(resp):
		return flag

	raise MumbleException('Flagstore 1 exploit 1 (badGenerator) failed')

@checker.exploit(1)
async def biasedNonceVuln(task: ExploitCheckerTaskMessage, di: DependencyInjector, logger: LoggerAdapter, random: Random):
	searcher = await di.get(FlagSearcher)
	logger = await di.get(LoggerAdapter)
	assert task.attack_info is not None

	client = await di.get(Session)
	pubkey = await getPubkey(client, logger)

	bitsKnown = 16
	requiredSigs = 21
	sigs = []
	_, sinId, sig0 = await confessGiven(client, logger, 0, pubkey)
	logger.critical(f'{sig0 = }')
	preproc = lambda x: list(map(int, x.strip(b' ().').split(b', ')))
	sig0 = preproc(sig0)
	z = int(sinId, 16)
	sigs.append({'r': sig0[0], 's': sig0[1], 'kp': 0})
	for _ in range(1, requiredSigs):
		_, _, sigx = await confessGiven(client, logger, 0, pubkey)
		sigx = preproc(sigx)
		sigs.append({'r': sigx[0], 's': sigx[1], 'kp': 0})

	recoveredPriv = recover_private_key(sigs, z, pubkey, 'SECP256R1', 'MSB', bitsKnown)
	signature = signraw(int(task.attack_info, 16), recoveredPriv)
	flagString = await retrieveSin(task.attack_info.encode(), f'({signature[0]}, {signature[1]})'.encode(), client, logger)



	if flag := searcher.search_flag(flagString):
		return flag

	raise MumbleException('Flagstore 1 exploit 1 (badGenerator) failed')



if __name__ == "__main__":
	import os
	os.environ['MONGO_USER'] = 'bbspriest_checker'
	os.environ['MONGO_PASSWORD'] = 'bbspriest_checker'

	checker.run(port = 8000)
