/*
    rsa.c -- RSA key handling
    Copyright (C) 2007-2022 Guus Sliepen <guus@tinc-vpn.org>

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
#include <openssl/rsa.h>

#define TINC_RSA_INTERNAL

#if OPENSSL_VERSION_MAJOR < 3
typedef RSA rsa_t;
#else
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <assert.h>

typedef EVP_PKEY rsa_t;
#endif

#include "log.h"
#include "../logger.h"
#include "../rsa.h"

// Set RSA keys

#if OPENSSL_VERSION_MAJOR >= 3
static EVP_PKEY *build_rsa_key(int selection, const BIGNUM *bn_n, const BIGNUM *bn_e, const BIGNUM *bn_d) {
	assert(bn_n);
	assert(bn_e);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

	if(!ctx) {
		openssl_err("initialize key context");
		return NULL;
	}

	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);

	if(bn_d) {
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, bn_d);
	}

	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
	EVP_PKEY *key = NULL;

	bool ok = EVP_PKEY_fromdata_init(ctx) > 0
	          && EVP_PKEY_fromdata(ctx, &key, selection, params) > 0;

	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);

	if(ok) {
		return key;
	}

	openssl_err("build key");
	return NULL;
}
#endif

static bool hex_to_bn(BIGNUM **bn, const char *hex) {
	return (size_t)BN_hex2bn(bn, hex) == strlen(hex);
}

static rsa_t *rsa_set_hex_key(const char *n, const char *e, const char *d) {
	rsa_t *rsa = NULL;
	BIGNUM *bn_n = NULL;
	BIGNUM *bn_e = NULL;
	BIGNUM *bn_d = NULL;

	if(!hex_to_bn(&bn_n, n) || !hex_to_bn(&bn_e, e) || (d && !hex_to_bn(&bn_d, d))) {
		goto exit;
	}

#if OPENSSL_VERSION_MAJOR < 3
	rsa = RSA_new();

	if(rsa) {
		RSA_set0_key(rsa, bn_n, bn_e, bn_d);
	}

#else
	int selection = bn_d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
	rsa = build_rsa_key(selection, bn_n, bn_e, bn_d);
#endif

exit:
#if OPENSSL_VERSION_MAJOR < 3

	if(!rsa)
#endif
	{
		BN_clear_free(bn_d);
		BN_free(bn_e);
		BN_free(bn_n);
	}

	return rsa;
}

rsa_t *rsa_set_hex_public_key(const char *n, const char *e) {
	return rsa_set_hex_key(n, e, NULL);
}

rsa_t *rsa_set_hex_private_key(const char *n, const char *e, const char *d) {
	return rsa_set_hex_key(n, e, d);
}

// Read PEM RSA keys

#if OPENSSL_VERSION_MAJOR >= 3
static rsa_t *read_key_from_pem(FILE *fp, int selection) {
	rsa_t *rsa = NULL;
	OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&rsa, "PEM", NULL, "RSA", selection, NULL, NULL);

	if(!ctx) {
		openssl_err("initialize decoder");
		return NULL;
	}

	bool ok = OSSL_DECODER_from_fp(ctx, fp);
	OSSL_DECODER_CTX_free(ctx);

	if(!ok) {
		rsa = NULL;
		openssl_err("read RSA key from file");
	}

	return rsa;
}
#endif

rsa_t *rsa_read_pem_public_key(FILE *fp) {
	rsa_t *rsa;

#if OPENSSL_VERSION_MAJOR < 3
	rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);

	if(!rsa) {
		rewind(fp);
		rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	}

#else
	rsa = read_key_from_pem(fp, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
#endif

	if(!rsa) {
		openssl_err("read RSA public key");
	}

	return rsa;
}

rsa_t *rsa_read_pem_private_key(FILE *fp) {
	rsa_t *rsa;

#if OPENSSL_VERSION_MAJOR < 3
	rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
#else
	rsa = read_key_from_pem(fp, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
#endif

	if(!rsa) {
		openssl_err("read RSA private key");
	}

	return rsa;
}

size_t rsa_size(const rsa_t *rsa) {
#if OPENSSL_VERSION_MAJOR < 3
	return RSA_size(rsa);
#else
	return EVP_PKEY_get_size(rsa);
#endif
}

#if OPENSSL_VERSION_MAJOR >= 3
// Initialize encryption or decryption context. Must return >0 on success, ≤0 on failure.
typedef int (enc_init_t)(EVP_PKEY_CTX *ctx);

// Encrypt or decrypt data. Must return >0 on success, ≤0 on failure.
typedef int (enc_process_t)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);

static bool rsa_encrypt_decrypt(rsa_t *rsa, const void *in, size_t len, void *out,
                                enc_init_t init, enc_process_t process) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, NULL);

	if(ctx) {
		size_t outlen = len;

		bool ok = init(ctx) > 0
		          && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) > 0
		          && process(ctx, out, &outlen, in, len) > 0
		          && outlen == len;

		EVP_PKEY_CTX_free(ctx);

		if(ok) {
			return true;
		}
	}

	return false;
}
#endif

bool rsa_public_encrypt(rsa_t *rsa, const void *in, size_t len, void *out) {
#if OPENSSL_VERSION_MAJOR < 3

	if((size_t)RSA_public_encrypt((int) len, in, out, rsa, RSA_NO_PADDING) == len) {
#else

	if(rsa_encrypt_decrypt(rsa, in, len, out, EVP_PKEY_encrypt_init, EVP_PKEY_encrypt)) {
#endif
		return true;
	}

	openssl_err("perform RSA encryption");
	return false;
}

bool rsa_private_decrypt(rsa_t *rsa, const void *in, size_t len, void *out) {
#if OPENSSL_VERSION_MAJOR < 3

	if((size_t)RSA_private_decrypt((int) len, in, out, rsa, RSA_NO_PADDING) == len) {
#else

	if(rsa_encrypt_decrypt(rsa, in, len, out, EVP_PKEY_decrypt_init, EVP_PKEY_decrypt)) {
#endif
		return true;
	}

	openssl_err("perform RSA decryption");
	return false;
}

void rsa_free(rsa_t *rsa) {
	if(rsa) {
#if OPENSSL_VERSION_MAJOR < 3
		RSA_free(rsa);
#else
		EVP_PKEY_free(rsa);
#endif
	}
}
