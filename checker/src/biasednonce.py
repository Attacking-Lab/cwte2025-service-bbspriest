# A biased nonce attack library adapted from Antoine Ferron - BitLogiK, typed and heavily adapted by me

from fpylll import LLL, BKZ, IntegerMatrix
import ecdsa_lib

from crypto import sign, O, Point, G
from hashlib import sha256
from random import randrange


def reduce_lattice(lattice, block_size=None):
	if block_size is None:
		print("LLL reduction")
		return LLL.reduction(lattice)
	print(f"BKZ reduction : block size = {block_size}")
	return BKZ.reduction(
		lattice,
		BKZ.Param(
			block_size=block_size,
			strategies=BKZ.DEFAULT_STRATEGY,
			auto_abort=True,
		),
	)

def test_result(mat, G: Point, pub: Point, curve: str):
	mod_n = ecdsa_lib.curve_n(curve)
	for row in mat:
		candidate = int(row[-2]) % mod_n
		if candidate > 0:
			cand1 = candidate
			cand2 = mod_n - candidate
			if G.mul(cand1) == pub:
				return cand1
			if G.mul(cand2) == pub:
				return cand2
	return 0


def build_matrix(sigs: list[dict[str, int]], curve: str, num_bits: int, bits_type: str, hash_val):
	num_sigs = len(sigs)
	n_order = ecdsa_lib.curve_n(curve)
	curve_card = 2 ** ecdsa_lib.curve_size(curve)
	lattice = IntegerMatrix(num_sigs + 2, num_sigs + 2)
	kbi = 2 ** num_bits
	inv = ecdsa_lib.inverse_mod
	if hash_val is not None:
		hash_i = hash_val
	if bits_type == "LSB":
		for i in range(num_sigs):
			lattice[i, i] = 2 * kbi * n_order
			if hash_val is None:
				hash_i = sigs[i]["hash"]
			lattice[num_sigs, i] = (
				2
				* kbi
				* (
					inv(kbi, n_order)
					* (sigs[i]["r"] * inv(sigs[i]["s"], n_order))
					% n_order
				)
			)
			lattice[num_sigs + 1, i] = (
				2
				* kbi
				* (
					inv(kbi, n_order)
					* (sigs[i]["kp"] - hash_i * inv(sigs[i]["s"], n_order))
					% n_order
				)
				+ n_order
			)
	else:
		# MSB
		for i in range(num_sigs):
			lattice[i, i] = 2 * kbi * n_order
			if hash_val is None:
				hash_i = sigs[i]["hash"]
			lattice[num_sigs, i] = (
				2 * kbi * ((sigs[i]["r"] * inv(sigs[i]["s"], n_order)) % n_order)
			)
			lattice[num_sigs + 1, i] = (
				2
				* kbi
				* (
					sigs[i]["kp"] * (curve_card // kbi)
					- hash_i * inv(sigs[i]["s"], n_order)
				)
				+ n_order
			)
	lattice[num_sigs, num_sigs] = 1
	lattice[num_sigs + 1, num_sigs + 1] = n_order
	return lattice


MINIMUM_BITS = 4
RECOVERY_SEQUENCE = [None, 15, 25, 40, 50, 60]
SIGNATURES_NUMBER_MARGIN = 1.03


def minimum_sigs_required(num_bits: int, curve_name: str):
	curve_size = ecdsa_lib.curve_size(curve_name)
	return int(SIGNATURES_NUMBER_MARGIN * 4 / 3 * curve_size / num_bits)


def recover_private_key(signatures_data: list[dict[str, int]], h_int: int, pubkey: Point, curve: str, bits_type: str, num_bits: int):
	# Is known bits > 4 ?
	# Change to 5 for 384 and 8 for 521 ?
	if num_bits < MINIMUM_BITS:
		print(
			"This script requires fixed known bits per signature, "
			f"and at least {MINIMUM_BITS}"
		)
		return False

	# Is there enough signatures ?
	n_sigs = minimum_sigs_required(num_bits, curve)
	if n_sigs > len(signatures_data):
		print(f'Not enough signatures, need >={n_sigs}')
		return False

	# sigs_data = random.sample(signatures_data, n_sigs)
	sigs_data = signatures_data

	print("Constructing matrix")
	lattice = build_matrix(sigs_data, curve, num_bits, bits_type, h_int)

	print("Solving matrix ...")
	lattice = reduce_lattice(lattice)
	res = test_result(lattice, G, pubkey, curve)
	if res:
		return res

	return False


if __name__ == "__main__":
	data = b'asdfasdf'
	bitsknown = 16
	priv = 0x69420
	print(f'{priv = }')
	z = int.from_bytes(sha256(data).digest()) % O
	for __ in range(100000):
		sigArr: list[dict[str, int]] = []
		for _ in range(21): # should need at least 256 / 16 = 16 sigs
			r, s = sign(data)
			sigArr.append({'r': r, 's': s, 'kp': 0})
		recoveredPriv = recover_private_key(sigArr, z, pubkey, 'SECP256R1', 'MSB', bitsknown)
		# print(f'{recoveredPriv = }')
		assert priv == recoveredPriv
