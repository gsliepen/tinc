/*
    rsa.c -- RSA key handling
    Copyright (C) 2007 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include <openssl/pem.h>
#include <openssl/err.h>

#include "logger.h"
#include "rsa.h"

// Set RSA keys

bool rsa_set_hex_public_key(rsa_t *rsa, char *n, char *e) {
	*rsa = RSA_new();
	BN_hex2bn(&(*rsa)->n, n);
	BN_hex2bn(&(*rsa)->e, e);
	return true;
}

bool rsa_set_hex_private_key(rsa_t *rsa, char *n, char *e, char *d) {
	*rsa = RSA_new();
	BN_hex2bn(&(*rsa)->n, n);
	BN_hex2bn(&(*rsa)->e, e);
	BN_hex2bn(&(*rsa)->d, d);
	return true;
}

// Read PEM RSA keys

bool rsa_read_pem_public_key(rsa_t *rsa, FILE *fp) {
	*rsa = PEM_read_RSAPublicKey(fp, rsa, NULL, NULL);

	if(*rsa)
		return true;
	
	*rsa = PEM_read_RSA_PUBKEY(fp, rsa, NULL, NULL);

	if(*rsa)
		return true;

	logger(LOG_ERR, "Unable to read RSA public key: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool rsa_read_pem_private_key(rsa_t *rsa, FILE *fp) {
	*rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);

	if(*rsa)
		return true;
	
	logger(LOG_ERR, "Unable to read RSA private key: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

size_t rsa_size(rsa_t *rsa) {
	return RSA_size(*rsa);
}

bool rsa_public_encrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	if(RSA_public_encrypt(len, in, out, *rsa, RSA_NO_PADDING) == len)
		return true;

	logger(LOG_ERR, "Unable to perform RSA encryption: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;	
}

bool rsa_private_decrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	if(RSA_private_decrypt(len, in, out, *rsa, RSA_NO_PADDING) == len)
		return true;

	logger(LOG_ERR, "Unable to perform RSA decryption: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;	
}

bool rsa_active(rsa_t *rsa) {
	return *rsa;
}

void rsa_free(rsa_t *rsa) {
	if(*rsa) {
		RSA_free(*rsa);
		*rsa = NULL;
	}
}
