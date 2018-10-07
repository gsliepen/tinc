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

#include "cipher.h"
#include "logger.h"
#include "xalloc.h"

static struct {
	const char *name;
	int algo;
	int mode;
	int nid;
} ciphertable[] = {
	{"none", GCRY_CIPHER_NONE, GCRY_CIPHER_MODE_NONE, 0},

	{NULL, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 92},
	{"blowfish", GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC, 91},
	{NULL, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB, 93},
	{NULL, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB, 94},

	{NULL, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 418},
	{"aes", GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 419},
	{NULL, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB, 421},
	{NULL, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OFB, 420},

	{NULL, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB, 422},
	{"aes192", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC, 423},
	{NULL, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB, 425},
	{NULL, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB, 424},

	{NULL, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 426},
	{"aes256", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 427},
	{NULL, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 429},
	{NULL, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB, 428},
};

static bool nametocipher(const char *name, int *algo, int *mode) {
	size_t i;

	for(i = 0; i < sizeof(ciphertable) / sizeof(*ciphertable); i++) {
		if(ciphertable[i].name && !strcasecmp(name, ciphertable[i].name)) {
			*algo = ciphertable[i].algo;
			*mode = ciphertable[i].mode;
			return true;
		}
	}

	return false;
}

static bool nidtocipher(int nid, int *algo, int *mode) {
	size_t i;

	for(i = 0; i < sizeof(ciphertable) / sizeof(*ciphertable); i++) {
		if(nid == ciphertable[i].nid) {
			*algo = ciphertable[i].algo;
			*mode = ciphertable[i].mode;
			return true;
		}
	}

	return false;
}

static bool ciphertonid(int algo, int mode, int *nid) {
	size_t i;

	for(i = 0; i < sizeof(ciphertable) / sizeof(*ciphertable); i++) {
		if(algo == ciphertable[i].algo && mode == ciphertable[i].mode) {
			*nid = ciphertable[i].nid;
			return true;
		}
	}

	return false;
}

static bool cipher_open(cipher_t *cipher, int algo, int mode) {
	gcry_error_t err;

	if(!ciphertonid(algo, mode, &cipher->nid)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Cipher %d mode %d has no corresponding nid!", algo, mode);
		return false;
	}

	if((err = gcry_cipher_open(&cipher->handle, algo, mode, 0))) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unable to initialise cipher %d mode %d: %s", algo, mode, gcry_strerror(err));
		return false;
	}

	cipher->keylen = gcry_cipher_get_algo_keylen(algo);
	cipher->blklen = gcry_cipher_get_algo_blklen(algo);
	cipher->key = xmalloc(cipher->keylen + cipher->blklen);
	cipher->padding = mode == GCRY_CIPHER_MODE_ECB || mode == GCRY_CIPHER_MODE_CBC;

	return true;
}

bool cipher_open_by_name(cipher_t *cipher, const char *name) {
	int algo, mode;

	if(!nametocipher(name, &algo, &mode)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown cipher name '%s'!", name);
		return false;
	}

	return cipher_open(cipher, algo, mode);
}

bool cipher_open_by_nid(cipher_t *cipher, int nid) {
	int algo, mode;

	if(!nidtocipher(nid, &algo, &mode)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown cipher ID %d!", nid);
		return false;
	}

	return cipher_open(cipher, algo, mode);
}

bool cipher_open_blowfish_ofb(cipher_t *cipher) {
	return cipher_open(cipher, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB);
}

void cipher_close(cipher_t *cipher) {
	if(cipher->handle) {
		gcry_cipher_close(cipher->handle);
		cipher->handle = NULL;
	}

	free(cipher->key);
	cipher->key = NULL;
}

size_t cipher_keylength(const cipher_t *cipher) {
	return cipher->keylen + cipher->blklen;
}

void cipher_get_key(const cipher_t *cipher, void *key) {
	memcpy(key, cipher->key, cipher->keylen + cipher->blklen);
}

bool cipher_set_key(cipher_t *cipher, void *key, bool encrypt) {
	memcpy(cipher->key, key, cipher->keylen + cipher->blklen);

	gcry_cipher_setkey(cipher->handle, cipher->key, cipher->keylen);
	gcry_cipher_setiv(cipher->handle, cipher->key + cipher->keylen, cipher->blklen);

	return true;
}

bool cipher_set_key_from_rsa(cipher_t *cipher, void *key, size_t len, bool encrypt) {
	memcpy(cipher->key, key + len - cipher->keylen, cipher->keylen + cipher->blklen);
	memcpy(cipher->key + cipher->keylen, key + len - cipher->keylen - cipher->blklen, cipher->blklen);

	gcry_cipher_setkey(cipher->handle, cipher->key, cipher->keylen);
	gcry_cipher_setiv(cipher->handle, cipher->key + cipher->keylen, cipher->blklen);

	return true;
}

bool cipher_regenerate_key(cipher_t *cipher, bool encrypt) {
	gcry_create_nonce(cipher->key, cipher->keylen + cipher->blklen);

	gcry_cipher_setkey(cipher->handle, cipher->key, cipher->keylen);
	gcry_cipher_setiv(cipher->handle, cipher->key + cipher->keylen, cipher->blklen);

	return true;
}

bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	gcry_error_t err;
	uint8_t pad[cipher->blklen];

	if(cipher->padding) {
		if(!oneshot) {
			return false;
		}

		size_t reqlen = ((inlen + cipher->blklen) / cipher->blklen) * cipher->blklen;

		if(*outlen < reqlen) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: not enough room for padding");
			return false;
		}

		uint8_t padbyte = reqlen - inlen;
		inlen = reqlen - cipher->blklen;

		for(int i = 0; i < cipher->blklen; i++)
			if(i < cipher->blklen - padbyte) {
				pad[i] = ((uint8_t *)indata)[inlen + i];
			} else {
				pad[i] = padbyte;
			}
	}

	if(oneshot) {
		gcry_cipher_setiv(cipher->handle, cipher->key + cipher->keylen, cipher->blklen);
	}

	if((err = gcry_cipher_encrypt(cipher->handle, outdata, *outlen, indata, inlen))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", gcry_strerror(err));
		return false;
	}

	if(cipher->padding) {
		if((err = gcry_cipher_encrypt(cipher->handle, outdata + inlen, cipher->blklen, pad, cipher->blklen))) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", gcry_strerror(err));
			return false;
		}

		inlen += cipher->blklen;
	}

	*outlen = inlen;
	return true;
}

bool cipher_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	gcry_error_t err;

	if(oneshot) {
		gcry_cipher_setiv(cipher->handle, cipher->key + cipher->keylen, cipher->blklen);
	}

	if((err = gcry_cipher_decrypt(cipher->handle, outdata, *outlen, indata, inlen))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: %s", gcry_strerror(err));
		return false;
	}

	if(cipher->padding) {
		if(!oneshot) {
			return false;
		}

		uint8_t padbyte = ((uint8_t *)outdata)[inlen - 1];

		if(padbyte == 0 || padbyte > cipher->blklen || padbyte > inlen) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: invalid padding");
			return false;
		}

		size_t origlen = inlen - padbyte;

		for(int i = inlen - 1; i >= origlen; i--)
			if(((uint8_t *)outdata)[i] != padbyte) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: invalid padding");
				return false;
			}

		*outlen = origlen;
	} else {
		*outlen = inlen;
	}

	return true;
}

int cipher_get_nid(const cipher_t *cipher) {
	return cipher->nid;
}

bool cipher_active(const cipher_t *cipher) {
	return cipher->nid != 0;
}
