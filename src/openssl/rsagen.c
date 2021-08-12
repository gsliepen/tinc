/*
    rsagen.c -- RSA key generation and export
    Copyright (C) 2008-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/pem.h>
#include <openssl/err.h>

#define TINC_RSA_INTERNAL
typedef RSA rsa_t;

#include "../logger.h"
#include "../rsagen.h"

/* This function prettyprints the key generation process */

static int indicator(int a, int b, BN_GENCB *cb) {
	(void)cb;

	switch(a) {
	case 0:
		fprintf(stderr, ".");
		break;

	case 1:
		fprintf(stderr, "+");
		break;

	case 2:
		fprintf(stderr, "-");
		break;

	case 3:
		switch(b) {
		case 0:
			fprintf(stderr, " p\n");
			break;

		case 1:
			fprintf(stderr, " q\n");
			break;

		default:
			fprintf(stderr, "?");
		}

		break;

	default:
		fprintf(stderr, "?");
	}

	return 1;
}

// Generate RSA key

rsa_t *rsa_generate(size_t bits, unsigned long exponent) {
	BIGNUM *bn_e = BN_new();
	rsa_t *rsa = RSA_new();
	BN_GENCB *cb = BN_GENCB_new();

	if(!bn_e || !rsa || !cb) {
		abort();
	}

	BN_set_word(bn_e, exponent);
	BN_GENCB_set(cb, indicator, NULL);

	int result = RSA_generate_key_ex(rsa, (int) bits, bn_e, cb);

	BN_GENCB_free(cb);
	BN_free(bn_e);

	if(!result) {
		fprintf(stderr, _("Error during key generation!\n"));
		RSA_free(rsa);
		return NULL;
	}

	return rsa;
}

// Write PEM RSA keys

bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp) {
	return PEM_write_RSAPublicKey(fp, rsa);
}

bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp) {
	return PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
}
