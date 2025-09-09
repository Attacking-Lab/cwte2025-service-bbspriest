#include <ctime>
#include <iostream>
#include <string>
#include <gmp.h>
#include <gmpxx.h>
#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>

class RSA {
	public:
		RSA(int seed);
		void generateKey(unsigned int bits);
		mpz_class generatePrime(unsigned int bits);
		std::string encrypt(const std::string& message);
		std::string decrypt(const std::string& message);
	// private:
		mpz_class n, e, d;
		gmp_randstate_t state;
};

RSA::RSA(int seed) {
	gmp_randinit_default(this->state);
	gmp_randseed_ui(this->state, seed);
	RSA::generateKey(1024);
	gmp_randclear(this->state);
}

mpz_class RSA::generatePrime(unsigned int bits) {
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
		// mpz_class diff = prime - randomNumber;
		// if (diff > (1 << maxbitdiff)) {
		// 	std::cout << "diff: " << diff.get_str(10) << '\n';
		// }
	// } while (prime - randomNumber >= (1 << maxbitdiff));
	} while (false);
	return prime;
};

void RSA::generateKey(unsigned int bits) {
	this->e = 65537;
	mpz_class phi;
	mpz_class p;
	mpz_class q;
	do {
		p = generatePrime(bits >> 1);
		q = generatePrime(bits >> 1);
		phi = (p - 1) * (q - 1);
	} while (mpz_invert(this->d.get_mpz_t(), this->e.get_mpz_t(), phi.get_mpz_t()) == 0);
	this->n = p * q;

	// NOTE: DEBUG
	// std::cout << "p = 0x" << p.get_str(16) << '\n';
	// std::cout << "q = 0x" << q.get_str(16) << '\n';
	// std::cout << "n = 0x" << this->n.get_str(16) << '\n';
	// mpz_class rp = p % (1 << 11);
	// mpz_class rq = q % (1 << 11);
	// std::cout << "rp = 0x" << rp.get_str(16) << '\n';
	// std::cout << "rq = 0x" << rq.get_str(16) << '\n';
}


std::string RSA::encrypt(const std::string& message) {
	// mpz_class m;
	// mpz_import(m.get_mpz_t(), message.size(), 1, sizeof(char), 0, 0, message.c_str());
	mpz_class m;
	m.set_str(message, 16);

	mpz_class c;
	mpz_powm(c.get_mpz_t(), m.get_mpz_t(), this->e.get_mpz_t(), this->n.get_mpz_t());

	return c.get_str(16);
}

std::string RSA::decrypt(const std::string& message) {
	// mpz_class m;
	// mpz_import(m.get_mpz_t(), message.size(), 1, sizeof(char), 0, 0, message.c_str());
	mpz_class c;
	c.set_str(message, 16);

	mpz_class m;
	mpz_powm(m.get_mpz_t(), c.get_mpz_t(), this->d.get_mpz_t(), this->n.get_mpz_t());

	return m.get_str(16);
}

RSA RSAkey(0);
void init(int x) {
	RSAkey = RSA(x);
}

std::string encrypthex(const std::string& message) {
	std::string ct = RSAkey.encrypt(message);
	if (ct.length() % 2 == 1) {
		ct = std::string("0") + ct;
	}
	return ct;
}

std::string decrypthex(const std::string& message) {
	std::string pt = RSAkey.decrypt(message);
	if (pt.length() % 2 == 1) {
		pt = std::string("0") + pt;
	}
	return pt;
}

std::string n() {
	return RSAkey.n.get_str(16);
}


namespace nb = nanobind;
using namespace nb::literals;

NB_MODULE(cryptoaccelerator, m) {
	m.doc() = "Did you know that Vikingskipet was built for the Ice Skating competition during the Winter Olympics in 1994";

	m.def("init", &init, "initialize the cryptoaccelerator");
	m.def("encrypt", &encrypthex, "encrypt");
	m.def("decrypt", &decrypthex, "decrypt");
	m.def("n", &n, "n");
}

