/*
    cipher.c -- Symmetric block cipher handling
    Copyright (C) 2007-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/rand.h>
#include <openssl/err.h>

#include "cipher.h"
#include "logger.h"
#include "xalloc.h"

typedef struct cipher_counter {
	unsigned char counter[EVP_MAX_IV_LENGTH];
	unsigned char block[EVP_MAX_IV_LENGTH];
	int n;
} cipher_counter_t;

static bool cipher_open(cipher_t *cipher) {
	EVP_CIPHER_CTX_init(&cipher->ctx);

	return true;
}

bool cipher_open_by_name(cipher_t *cipher, const char *name) {
	cipher->cipher = EVP_get_cipherbyname(name);

	if(cipher->cipher)
		return cipher_open(cipher);

	logger(DEBUG_ALWAYS, LOG_ERR, "Unknown cipher name '%s'!", name);
	return false;
}

bool cipher_open_by_nid(cipher_t *cipher, int nid) {
	cipher->cipher = EVP_get_cipherbynid(nid);

	if(cipher->cipher)
		return cipher_open(cipher);

	logger(DEBUG_ALWAYS, LOG_ERR, "Unknown cipher nid %d!", nid);
	return false;
}

bool cipher_open_blowfish_ofb(cipher_t *cipher) {
	cipher->cipher = EVP_bf_ofb();
	return cipher_open(cipher);
}

void cipher_close(cipher_t *cipher) {
	EVP_CIPHER_CTX_cleanup(&cipher->ctx);
	free(cipher->counter);
	cipher->counter = NULL;
}

size_t cipher_keylength(const cipher_t *cipher) {
	return cipher->cipher->key_len + cipher->cipher->block_size;
}

bool cipher_set_key(cipher_t *cipher, void *key, bool encrypt) {
	bool result;

	if(encrypt)
		result = EVP_EncryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)key, (unsigned char *)key + cipher->cipher->key_len);
	else
		result = EVP_DecryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)key, (unsigned char *)key + cipher->cipher->key_len);

	if(result)
		return true;

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while setting key: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_set_key_from_rsa(cipher_t *cipher, void *key, size_t len, bool encrypt) {
	bool result;

	if(encrypt)
		result = EVP_EncryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)key + len - cipher->cipher->key_len, (unsigned char *)key + len - cipher->cipher->iv_len - cipher->cipher->key_len);
	else
		result = EVP_DecryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)key + len - cipher->cipher->key_len, (unsigned char *)key + len - cipher->cipher->iv_len - cipher->cipher->key_len);

	if(result)
		return true;

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while setting key: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_set_counter(cipher_t *cipher, const void *counter, size_t len) {
	if(len > cipher->cipher->block_size - 4) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Counter too long");
		abort();
	}

	memcpy(cipher->counter->counter + cipher->cipher->block_size - len, counter, len);
	memset(cipher->counter->counter, 0, 4);
	cipher->counter->n = 0;

	return true;
}

bool cipher_set_counter_key(cipher_t *cipher, void *key) {
	int result = EVP_EncryptInit_ex(&cipher->ctx, cipher->cipher, NULL, (unsigned char *)key, NULL);
	if(!result) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while setting key: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	if(!cipher->counter)
		cipher->counter = xmalloc_and_zero(sizeof *cipher->counter);
	else
		cipher->counter->n = 0;

	memcpy(cipher->counter->counter, (unsigned char *)key + cipher->cipher->key_len, cipher->cipher->block_size);

	return true;
}

bool cipher_counter_xor(cipher_t *cipher, const void *indata, size_t inlen, void *outdata) {
	if(!cipher->counter) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Counter not initialized");
		return false;
	}

	const unsigned char *in = indata;
	unsigned char *out = outdata;

	while(inlen--) {
		// Encrypt the new counter value if we need it
		if(!cipher->counter->n) {
			int len;
			if(!EVP_EncryptUpdate(&cipher->ctx, cipher->counter->block, &len, cipher->counter->counter, cipher->cipher->block_size)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", ERR_error_string(ERR_get_error(), NULL));
				return false;
			}

			// Increase the counter value
			for(int i = 0; i < cipher->cipher->block_size; i++)
				if(++cipher->counter->counter[i])
					break;
		}

		*out++ = *in++ ^ cipher->counter->counter[cipher->counter->n++];

		if(cipher->counter->n >= cipher->cipher->block_size)
			cipher->counter->n = 0;
	}

	return true;
}


bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	if(oneshot) {
		int len, pad;
		if(EVP_EncryptInit_ex(&cipher->ctx, NULL, NULL, NULL, NULL)
				&& EVP_EncryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, indata, inlen)
				&& EVP_EncryptFinal(&cipher->ctx, (unsigned char *)outdata + len, &pad)) {
			if(outlen) *outlen = len + pad;
			return true;
		}
	} else {
		int len;
		if(EVP_EncryptUpdate(&cipher->ctx, outdata, &len, indata, inlen)) {
			if(outlen) *outlen = len;
			return true;
		}
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	if(oneshot) {
		int len, pad;
		if(EVP_DecryptInit_ex(&cipher->ctx, NULL, NULL, NULL, NULL)
				&& EVP_DecryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, indata, inlen)
				&& EVP_DecryptFinal(&cipher->ctx, (unsigned char *)outdata + len, &pad)) {
			if(outlen) *outlen = len + pad;
			return true;
		}
	} else {
		int len;
		if(EVP_EncryptUpdate(&cipher->ctx, outdata, &len, indata, inlen)) {
			if(outlen) *outlen = len;
			return true;
		}
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

int cipher_get_nid(const cipher_t *cipher) {
	return cipher->cipher ? cipher->cipher->nid : 0;
}

bool cipher_active(const cipher_t *cipher) {
	return cipher->cipher && cipher->cipher->nid != 0;
}
