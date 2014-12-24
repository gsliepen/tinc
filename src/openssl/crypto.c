/*
    crypto.c -- Cryptographic miscellaneous functions and initialisation
    Copyright (C) 2007-2014 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "../system.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include "../crypto.h"

#ifndef HAVE_MINGW

static int random_fd = -1;

static void random_init(void) {
	random_fd = open("/dev/urandom", O_RDONLY);
	if(random_fd < 0)
		random_fd = open("/dev/random", O_RDONLY);
	if(random_fd < 0) {
		fprintf(stderr, "Could not open source of random numbers: %s\n", strerror(errno));
		abort();
	}
}

static void random_exit(void) {
	close(random_fd);
}

void randomize(void *out, size_t outlen) {
	while(outlen) {
		size_t len = read(random_fd, out, outlen);
		if(len <= 0) {
			if(errno == EAGAIN || errno == EINTR)
				continue;
			fprintf(stderr, "Could not read random numbers: %s\n", strerror(errno));
			abort();
		}
		out += len;
		outlen -= len;
	}
}

#else

#include <wincrypt.h>
HCRYPTPROV prov;

void random_init(void) {
	if(!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		fprintf(stderr, "CryptAcquireContext() failed!\n");
		abort();
	}
}

void random_exit(void) {
	CryptReleaseContext(prov, 0);
}

void randomize(void *out, size_t outlen) {
	if(!CryptGenRandom(prov, outlen, out)) {
		fprintf(stderr, "CryptGenRandom() failed\n");
		abort();
	}
}

#endif

void crypto_init(void) {
	random_init();

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	if(!RAND_status()) {
		fprintf(stderr, "Not enough entropy for the PRNG!\n");
		abort();
	}
}

void crypto_exit(void) {
	EVP_cleanup();
	ERR_free_strings();
	ENGINE_cleanup();
	random_exit();
}
