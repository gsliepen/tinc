/*
    rsagen.c -- RSA key generation and export
    Copyright (C) 2008-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/pem.h>
#include <openssl/err.h>

#define TINC_RSA_INTERNAL

#if OPENSSL_VERSION_MAJOR < 3
typedef RSA rsa_t;
#else
typedef EVP_PKEY rsa_t;
#include <openssl/encoder.h>
#include <openssl/evp.h>
#endif

#include "../logger.h"
#include "../rsagen.h"
#include "log.h"

#if OPENSSL_VERSION_MAJOR < 3
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
#endif

// Generate RSA key

rsa_t *rsa_generate(size_t bits, unsigned long exponent) {
	BIGNUM *bn_e = BN_new();
	rsa_t *rsa = NULL;

	if(!bn_e) {
		abort();
	}

	BN_set_word(bn_e, exponent);

#if OPENSSL_VERSION_MAJOR < 3
	rsa = RSA_new();
	BN_GENCB *cb = BN_GENCB_new();

	if(!rsa || !cb) {
		abort();
	}

	BN_GENCB_set(cb, indicator, NULL);

	int result = RSA_generate_key_ex(rsa, (int) bits, bn_e, cb);

	BN_GENCB_free(cb);

	if(!result) {
		fprintf(stderr, "Error during key generation!\n");
		RSA_free(rsa);
		rsa = NULL;
	}

#else
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

	bool ok = ctx
	          && EVP_PKEY_keygen_init(ctx) > 0
	          && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn_e) > 0
	          && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)bits) > 0
	          && EVP_PKEY_keygen(ctx, &rsa) > 0;

	if(ctx) {
		EVP_PKEY_CTX_free(ctx);
	}

	if(!ok) {
		openssl_err("generate key");
		rsa = NULL;
	}

#endif

	BN_free(bn_e);

	return rsa;
}

// Write PEM RSA keys

#if OPENSSL_VERSION_MAJOR >= 3
static bool write_key_to_pem(const rsa_t *rsa, FILE *fp, int selection) {
	OSSL_ENCODER_CTX *enc = OSSL_ENCODER_CTX_new_for_pkey(rsa, selection, "PEM", NULL, NULL);

	if(!enc) {
		openssl_err("create encoder context");
		return false;
	}

	bool ok = OSSL_ENCODER_to_fp(enc, fp);
	OSSL_ENCODER_CTX_free(enc);

	if(!ok) {
		openssl_err("write key to file");
	}

	return ok;
}
#endif

bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp) {
#if OPENSSL_VERSION_MAJOR < 3
	return PEM_write_RSAPublicKey(fp, rsa);
#else
	return write_key_to_pem(rsa, fp, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
#endif
}

bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp) {
#if OPENSSL_VERSION_MAJOR < 3
	return PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
#else
	return write_key_to_pem(rsa, fp, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
#endif
}
