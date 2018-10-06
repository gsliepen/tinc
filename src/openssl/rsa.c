/*
    rsa.c -- RSA key handling
    Copyright (C) 2007-2013 Guus Sliepen <guus@tinc-vpn.org>

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
typedef RSA rsa_t;

#include "../logger.h"
#include "../rsa.h"

// Set RSA keys

#ifndef HAVE_RSA_SET0_KEY
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
	BN_free(r->n);
	r->n = n;
	BN_free(r->e);
	r->e = e;
	BN_free(r->d);
	r->d = d;
	return 1;
}
#endif

rsa_t *rsa_set_hex_public_key(char *n, char *e) {
	BIGNUM *bn_n = NULL;
	BIGNUM *bn_e = NULL;

	if((size_t)BN_hex2bn(&bn_n, n) != strlen(n) || (size_t)BN_hex2bn(&bn_e, e) != strlen(e)) {
		BN_free(bn_e);
		BN_free(bn_n);
		return false;
	}

	rsa_t *rsa = RSA_new();

	if(!rsa) {
		return NULL;
	}

	RSA_set0_key(rsa, bn_n, bn_e, NULL);

	return rsa;
}

rsa_t *rsa_set_hex_private_key(char *n, char *e, char *d) {
	BIGNUM *bn_n = NULL;
	BIGNUM *bn_e = NULL;
	BIGNUM *bn_d = NULL;

	if((size_t)BN_hex2bn(&bn_n, n) != strlen(n) || (size_t)BN_hex2bn(&bn_e, e) != strlen(e) || (size_t)BN_hex2bn(&bn_d, d) != strlen(d)) {
		BN_free(bn_d);
		BN_free(bn_e);
		BN_free(bn_n);
		return false;
	}

	rsa_t *rsa = RSA_new();

	if(!rsa) {
		return NULL;
	}

	RSA_set0_key(rsa, bn_n, bn_e, bn_d);

	return rsa;
}

// Read PEM RSA keys

rsa_t *rsa_read_pem_public_key(FILE *fp) {
	rsa_t *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);

	if(!rsa) {
		rewind(fp);
		rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	}

	if(!rsa) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read RSA public key: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	return rsa;
}

rsa_t *rsa_read_pem_private_key(FILE *fp) {
	rsa_t *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);

	if(!rsa) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read RSA private key: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	return rsa;
}

size_t rsa_size(rsa_t *rsa) {
	return RSA_size(rsa);
}

bool rsa_public_encrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	if((size_t)RSA_public_encrypt(len, in, out, rsa, RSA_NO_PADDING) == len) {
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Unable to perform RSA encryption: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool rsa_private_decrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	if((size_t)RSA_private_decrypt(len, in, out, rsa, RSA_NO_PADDING) == len) {
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Unable to perform RSA decryption: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool rsa_active(rsa_t *rsa) {
	return rsa;
}

void rsa_free(rsa_t *rsa) {
	if(rsa) {
		RSA_free(rsa);
	}
}
