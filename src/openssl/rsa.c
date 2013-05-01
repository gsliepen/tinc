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

#define __TINC_RSA_INTERNAL__
typedef RSA rsa_t;

#include "../logger.h"
#include "../rsa.h"

// Set RSA keys

rsa_t *rsa_set_hex_public_key(char *n, char *e) {
	rsa_t *rsa = RSA_new();
	if(!rsa)
		return NULL;

	if(BN_hex2bn(&rsa->n, n) != strlen(n) || BN_hex2bn(&rsa->e, e) != strlen(e)) {
		RSA_free(rsa);
		return false;
	}

	return rsa;
}

rsa_t *rsa_set_hex_private_key(char *n, char *e, char *d) {
	rsa_t *rsa = RSA_new();
	if(!rsa)
		return NULL;

	if(BN_hex2bn(&rsa->n, n) != strlen(n) || BN_hex2bn(&rsa->e, e) != strlen(e) || BN_hex2bn(&rsa->d, d) != strlen(d)) {
		RSA_free(rsa);
		return false;
	}

	return rsa;
}

// Read PEM RSA keys

rsa_t *rsa_read_pem_public_key(FILE *fp) {
	rsa_t *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);

	if(!rsa)
		rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);

	if(!rsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read RSA public key: %s", ERR_error_string(ERR_get_error(), NULL));

	return rsa;
}

rsa_t *rsa_read_pem_private_key(FILE *fp) {
	rsa_t *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);

	if(!rsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read RSA private key: %s", ERR_error_string(ERR_get_error(), NULL));

	return rsa;
}

size_t rsa_size(rsa_t *rsa) {
	return RSA_size(rsa);
}

bool rsa_public_encrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	if(RSA_public_encrypt(len, in, out, rsa, RSA_NO_PADDING) == len)
		return true;

	logger(DEBUG_ALWAYS, LOG_ERR, "Unable to perform RSA encryption: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool rsa_private_decrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	if(RSA_private_decrypt(len, in, out, rsa, RSA_NO_PADDING) == len)
		return true;

	logger(DEBUG_ALWAYS, LOG_ERR, "Unable to perform RSA decryption: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool rsa_active(rsa_t *rsa) {
	return rsa;
}

void rsa_free(rsa_t *rsa) {
	if(rsa)
		RSA_free(rsa);
}
