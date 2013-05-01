/*
    ecdsa.c -- ECDSA key handling
    Copyright (C) 2011-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#define __TINC_ECDSA_INTERNAL__
typedef EC_KEY ecdsa_t;

#include "../logger.h"
#include "../ecdsa.h"
#include "../utils.h"
#include "../xalloc.h"

// Get and set ECDSA keys
//
ecdsa_t *ecdsa_set_base64_public_key(const char *p) {
	ecdsa_t *ecdsa = EC_KEY_new_by_curve_name(NID_secp521r1);
	if(!ecdsa) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "EC_KEY_new_by_curve_name failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	int len = strlen(p);
	unsigned char pubkey[len / 4 * 3 + 3];
	const unsigned char *ppubkey = pubkey;
	len = b64decode(p, (char *)pubkey, len);

	if(!o2i_ECPublicKey(&ecdsa, &ppubkey, len)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "o2i_ECPublicKey failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ecdsa);
		return NULL;
	}

	return ecdsa;
}

char *ecdsa_get_base64_public_key(ecdsa_t *ecdsa) {
	unsigned char *pubkey = NULL;
	int len = i2o_ECPublicKey(ecdsa, &pubkey);

	char *base64 = xmalloc(len * 4 / 3 + 5);
	b64encode((char *)pubkey, base64, len);

	free(pubkey);

	return base64;
}

// Read PEM ECDSA keys

ecdsa_t *ecdsa_read_pem_public_key(FILE *fp) {
	ecdsa_t *ecdsa = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);

	if(!ecdsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read ECDSA public key: %s", ERR_error_string(ERR_get_error(), NULL));

	return ecdsa;
}

ecdsa_t *ecdsa_read_pem_private_key(FILE *fp) {
	ecdsa_t *ecdsa = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);

	if(!ecdsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read ECDSA private key: %s", ERR_error_string(ERR_get_error(), NULL));

	return ecdsa;
}

size_t ecdsa_size(ecdsa_t *ecdsa) {
	return ECDSA_size(ecdsa);
}

// TODO: standardise output format?

bool ecdsa_sign(ecdsa_t *ecdsa, const void *in, size_t len, void *sig) {
	unsigned int siglen = ECDSA_size(ecdsa);

	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA512(in, len, hash);

	memset(sig, 0, siglen);

	if(!ECDSA_sign(0, hash, sizeof hash, sig, &siglen, ecdsa)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "ECDSA_sign() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	return true;
}

bool ecdsa_verify(ecdsa_t *ecdsa, const void *in, size_t len, const void *sig) {
	unsigned int siglen = ECDSA_size(ecdsa);

	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA512(in, len, hash);

	if(!ECDSA_verify(0, hash, sizeof hash, sig, siglen, ecdsa)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "ECDSA_verify() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	return true;
}

bool ecdsa_active(ecdsa_t *ecdsa) {
	return ecdsa;
}

void ecdsa_free(ecdsa_t *ecdsa) {
	if(ecdsa)
		EC_KEY_free(ecdsa);
}
