#include <cassert>
#include <iostream>
#include <tuple>
#include <vector>
#include <utility>
#include <gmp.h>
#include <gmpxx.h>
#include <chrono>

int maxbitdiff = 12;
gmp_randstate_t state;
mpz_class generatePrime(unsigned int bits) {
	mpz_class randomNumber;
	mpz_class prime;
	mpz_class low;
	mpz_ui_pow_ui(low.get_mpz_t(), 2, bits >> 2);
	do {
		mpz_urandomb(randomNumber.get_mpz_t(), state, (bits >> 2) - 1);
		randomNumber += low;
		randomNumber += -(randomNumber % 16);
		randomNumber *= randomNumber;
		randomNumber *= randomNumber;
		mpz_nextprime(prime.get_mpz_t(), randomNumber.get_mpz_t());
		mpz_class diff = prime - randomNumber;
		// if (diff > (1 << maxbitdiff)) {
		// 	std::cout << "diff: " << diff.get_str(10) << '\n';
		// }
	// } while (prime - randomNumber >= (1 << maxbitdiff));
	} while (false);
	return prime;
};

std::vector<mpz_class> quadraticFormula(const mpz_class& b, const mpz_class& c) {
	// Calculate the discriminant: Dsq = b^2 - 4*a*c, where a=1.
	mpz_class Dsq = b * b - 4 * c;

	// If the discriminant is negative or not a perfect square, there are no integer roots.
	if (Dsq < 0 || mpz_perfect_square_p(Dsq.get_mpz_t()) == 0) {
		return {};
	}

	// Calculate the integer square root of the discriminant.
	mpz_class D = sqrt(Dsq);

	// Calculate the numerators of the two possible roots.
	mpz_class r0 = -b + D;
	mpz_class r1 = -b - D;

	std::vector<mpz_class> roots;
	roots.reserve(2); // Pre-allocate memory for up to two roots.

	// The roots are r / (2*a), where a=1. For an integer solution, the numerator must be even.
	if (mpz_even_p(r0.get_mpz_t())) {
		roots.push_back(r0 / 2);
	}
	if (mpz_even_p(r1.get_mpz_t())) {
		roots.push_back(r1 / 2);
	}

	return roots;
}

mpz_class totalIters = 0;
std::pair<mpz_class, mpz_class> factor(const mpz_class& N, const mpz_class& rp, const mpz_class& rq, const int maxIters = 100'000) {
	mpz_class i = sqrt(rp * rq);
	const mpz_class initial_i = i;
	
	// Pre-calculate loop-invariant values for efficiency.
	const mpz_class N_sqrt = sqrt(N);
	const mpz_class rp_mul_rq = rp * rq;
	
	// The main loop of the algorithm.
	while (true) {
		mpz_class term = N_sqrt - i;
		mpz_class sigma = term * term;
		if (sigma == 0) {
			continue;
		}
		mpz_class z = (N - rp_mul_rq) % sigma;

		// Find roots of the quadratic equation.
		std::vector<mpz_class> roots = quadraticFormula(-z, sigma * rp_mul_rq);

		// Check each root to see if it leads to a factor of N.
		for (const auto& root : roots) {
			if (root % rp == 0) {
				mpz_class p = root / rp + rq;
				if (p != 0 && N % p == 0) {
					// std::cout << "iters: " << i - initial_i << '\n';
					totalIters += i - initial_i;
					return {p, N / p};
				}
			}
			if (root % rq == 0) {
				mpz_class p = root / rq + rp;
				if (p != 0 && N % p == 0) {
					// std::cout << "iters: " << i - initial_i << '\n';
					totalIters += i - initial_i;
					return {p, N / p};
				}
			}
		}

		i++;
		if (i - initial_i > maxIters) {
			return {1, 1};
		}
	}
}

std::pair<mpz_class, mpz_class> blindfactor(const mpz_class& N, const mpz_class& rp = 0, const mpz_class& rq = 0) {
	const int bailoutThreshold = 1 << 20;
	int initialIters = 1024;
	mpz_class mod = (1 << maxbitdiff);
	mpz_class Nred = N % mod;
	std::vector<std::pair<mpz_class, mpz_class>> candidates;
	for (mpz_class a = 1; a < mod; a += 2) {
		mpz_class a_inv;
		mpz_invert(a_inv.get_mpz_t(), a.get_mpz_t(), mod.get_mpz_t());
		mpz_class b = (a_inv * Nred) % mod;
		candidates.push_back({a, b});
	}
	for (int iters = initialIters; iters <= bailoutThreshold; iters *= 4) {
		if (iters != initialIters) {
			// std::cout << "Expanding to: " << iters << '\n';
		}
		for (size_t ctr = 0; ctr < candidates.size(); ++ctr) {
			std::pair<mpz_class, mpz_class> ret = factor(N, candidates[ctr].first, candidates[ctr].second, iters);
			if (ret.first != 1) {
				return ret;
			}
		}
	}

	// std::cout << "FAILED!" << std::endl;
	return {1, 1};
}

void test() {
	gmp_randinit_default(state);
	gmp_randseed_ui(state, 0x69420);
	int bits = 1024;
	int bitsPerPrime = bits >> 1;
	std::vector<std::tuple<mpz_class, mpz_class, mpz_class>> workload;
	auto genstart = std::chrono::high_resolution_clock::now();
	int iters = 4'00;
	// int iters = 1'000;
	for (int idx = 0; idx < iters; ++idx) {
		mpz_class p = generatePrime(bitsPerPrime);
		mpz_class q = generatePrime(bitsPerPrime);
		mpz_class N = p * q;
		mpz_class rp = p % (1 << maxbitdiff);
		mpz_class rq = q % (1 << maxbitdiff);
		// avgPrimeGap += rp; C++ gmp read in big number from std cin 
		// avgPrimeGap += rq;
		workload.push_back({N, rp, rq});
	}

	std::cout << "N = " << generatePrime(bitsPerPrime) * generatePrime(bitsPerPrime) << '\n';

	auto genend = std::chrono::high_resolution_clock::now();
    auto gentime = std::chrono::duration_cast<std::chrono::milliseconds>(genend - genstart);
	std::cout << "Generation time: " << gentime.count() << " ms (" << gentime.count() / iters << " ms/gen)\n";

	auto factorstart = std::chrono::high_resolution_clock::now();
	int fails = 0;
	for (const auto& [N, rp, rq] : workload) {
		// std::pair<mpz_class, mpz_class> factors = factor(N, rp, rq);
		std::pair<mpz_class, mpz_class> factors = blindfactor(N, rp, rq);
		if (factors.first == 1 && factors.second == 1) {
			fails += 1;
		}
	}
	auto factorend = std::chrono::high_resolution_clock::now();
    auto factortime = std::chrono::duration_cast<std::chrono::milliseconds>(factorend - factorstart);
	std::cout << "Factoring time: " << factortime.count() << " ms (" << factortime.count() / iters << " ms/fac)\n";
	std::cout << "Fails: " << fails << '\n';
	std::cout << "Iter/fac: " << (double)(totalIters.get_ui()) / iters << '\n';
}

int main(int argc, char* argv[]) {
	// test();
	mpz_class N;
	if (argc == 1) {
		std::cin >> N;
	} else if (argc == 2) {
		assert(mpz_set_str(N.get_mpz_t(), argv[1], 0) == 0);
	} else {
		assert(false);
	}
	std::pair<mpz_class, mpz_class> fac = blindfactor(N);
	std::cout << fac.first.get_str(10) << ", " << fac.second.get_str(10) << std::endl;
}
