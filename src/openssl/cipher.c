/*
    cipher.c -- Symmetric block cipher handling
    Copyright (C) 2007 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#include "system.h"

#include <openssl/rand.h>
#include <openssl/err.h>

#include "cipher.h"
#include "logger.h"
#include "xalloc.h"

static bool cipher_open(cipher_t *cipher) {
	cipher->keylen = cipher->cipher->key_len;
	cipher->blklen = cipher->cipher->iv_len;

	cipher->key = xmalloc(cipher->keylen + cipher->blklen);

	EVP_CIPHER_CTX_init(&cipher->ctx);

	return true;
}

bool cipher_open_by_name(cipher_t *cipher, const char *name) {
	cipher->cipher = EVP_get_cipherbyname(name);

	if(cipher->cipher)
		return cipher_open(cipher);

	logger(LOG_DEBUG, _("Unknown cipher name '%s'!"), name);
	return false;
}

bool cipher_open_by_nid(cipher_t *cipher, int nid) {
	cipher->cipher = EVP_get_cipherbynid(nid);

	if(cipher->cipher)
		return cipher_open(cipher);

	logger(LOG_DEBUG, _("Unknown cipher nid %d!"), nid);
	return false;
}

bool cipher_open_blowfish_ofb(cipher_t *cipher) {
	cipher->cipher = EVP_bf_ofb();
	return cipher_open(cipher);
}

void cipher_close(cipher_t *cipher) {
	EVP_CIPHER_CTX_cleanup(&cipher->ctx);

	if(cipher->key) {
		free(cipher->key);
		cipher->key = NULL;
	}
}

size_t cipher_keylength(const cipher_t *cipher) {
	return cipher->keylen + cipher->blklen;
}

void cipher_get_key(const cipher_t *cipher, void *key) {
	memcpy(key, cipher->key, cipher->keylen + cipher->blklen);
}

bool cipher_set_key(cipher_t *cipher, void *key, bool encrypt) {
	memcpy(cipher->key, key, cipher->keylen + cipher->blklen);
	bool result;

	if(encrypt)
		result = EVP_EncryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)cipher->key, (unsigned char *)cipher->key + cipher->keylen);
	else
		result = EVP_DecryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)cipher->key, (unsigned char *)cipher->key + cipher->keylen);

	if(result)
		return true;

	logger(LOG_ERR, _("Error while setting key: %s"), ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_set_key_from_rsa(cipher_t *cipher, void *key, size_t len, bool encrypt) {
	memcpy(cipher->key, key + len - (size_t)cipher->keylen, cipher->keylen);
	memcpy(cipher->key + cipher->keylen, key + len - (size_t)cipher->keylen - (size_t)cipher->blklen, cipher->blklen);
	bool result;

	if(encrypt)
		result = EVP_EncryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)cipher->key, (unsigned char *)cipher->key + cipher->keylen);
	else
		result = EVP_DecryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)cipher->key, (unsigned char *)cipher->key + cipher->keylen);

	if(result)
		return true;

	logger(LOG_ERR, _("Error while setting key: %s"), ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_regenerate_key(cipher_t *cipher, bool encrypt) {
	bool result;

	RAND_pseudo_bytes((unsigned char *)cipher->key, cipher->keylen + cipher->blklen);

	if(encrypt)
		result = EVP_EncryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)cipher->key, (unsigned char *)cipher->key + cipher->keylen);
	else
		result = EVP_DecryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)cipher->key, (unsigned char *)cipher->key + cipher->keylen);

	if(result)
		return true;
	
	logger(LOG_ERR, _("Error while regenerating key: %s"), ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	if(oneshot) {
		int len = *outlen, pad;
		if(EVP_EncryptInit_ex(&cipher->ctx, NULL, NULL, NULL, NULL)
				&&EVP_EncryptUpdate(&cipher->ctx, outdata, &len, indata, inlen)
				&& EVP_EncryptFinal(&cipher->ctx, outdata + len, &pad)) {
			*outlen = len + pad;
			return true;
		}
	} else {
		int len = *outlen;
		if(EVP_EncryptUpdate(&cipher->ctx, outdata, &len, indata, inlen)) {
			*outlen = len;
			return true;
		}
	}

	logger(LOG_ERR, _("Error while encrypting: %s"), ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	if(oneshot) {
		int len = *outlen, pad;
		if(EVP_DecryptInit_ex(&cipher->ctx, NULL, NULL, NULL, NULL)
				&& EVP_DecryptUpdate(&cipher->ctx, outdata, &len, indata, inlen)
				&& EVP_DecryptFinal(&cipher->ctx, outdata + len, &pad)) {
			*outlen = len + pad;
			return true;
		}
	} else {
		int len = *outlen;
		if(EVP_EncryptUpdate(&cipher->ctx, outdata, &len, indata, inlen)) {
			*outlen = len;
			return true;
		}
	}

	logger(LOG_ERR, _("Error while encrypting: %s"), ERR_error_string(ERR_get_error(), NULL));
	return false;
}

int cipher_get_nid(const cipher_t *cipher) {
	return cipher->cipher ? cipher->cipher->nid : 0;
}

bool cipher_active(const cipher_t *cipher) {
	return cipher->cipher && cipher->cipher->nid != 0;
}
