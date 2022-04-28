/*
    cipher.c -- Symmetric block cipher handling
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

#include "cipher.h"
#include "../cipher.h"
#include "../logger.h"
#include "../xalloc.h"

typedef enum gcry_cipher_algos cipher_algo_t;
typedef enum gcry_cipher_modes cipher_mode_t;

static struct {
	const char *name;
	cipher_algo_t algo;
	cipher_mode_t mode;
	nid_t nid;
} ciphertable[] = {
	{"none", GCRY_CIPHER_NONE, GCRY_CIPHER_MODE_NONE, 0},

	{NULL,       GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 92},
	{"blowfish", GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC, 91},
	{NULL,       GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB, 93},
	{NULL,       GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB, 94},

	{"aes-128-ecb", GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 418},
	{"aes-128-cbc", GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 419},
	{"aes-128-cfb", GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB, 421},
	{"aes-128-ofb", GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OFB, 420},

	{"aes-192-ecb", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB, 422},
	{"aes-192-cbc", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC, 423},
	{"aes-192-cfb", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB, 425},
	{"aes-192-ofb", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB, 424},

	{"aes-256-ecb", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 426},
	{"aes-256-cbc", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 427},
	{"aes-256-cfb", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 429},
	{"aes-256-ofb", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB, 428},
};

static bool nametocipher(const char *name, cipher_algo_t *algo, cipher_mode_t *mode) {
	for(size_t i = 0; i < sizeof(ciphertable) / sizeof(*ciphertable); i++) {
		if(ciphertable[i].name && !strcasecmp(name, ciphertable[i].name)) {
			*algo = ciphertable[i].algo;
			*mode = ciphertable[i].mode;
			return true;
		}
	}

	return false;
}

static bool nidtocipher(cipher_algo_t *algo, cipher_mode_t *mode, nid_t nid) {
	for(size_t i = 0; i < sizeof(ciphertable) / sizeof(*ciphertable); i++) {
		if(nid == ciphertable[i].nid) {
			*algo = ciphertable[i].algo;
			*mode = ciphertable[i].mode;
			return true;
		}
	}

	return false;
}

static bool ciphertonid(nid_t *nid, cipher_algo_t algo, cipher_mode_t mode) {
	for(size_t i = 0; i < sizeof(ciphertable) / sizeof(*ciphertable); i++) {
		if(algo == ciphertable[i].algo && mode == ciphertable[i].mode) {
			*nid = ciphertable[i].nid;
			return true;
		}
	}

	return false;
}

static bool cipher_open(cipher_t *cipher, cipher_algo_t algo, cipher_mode_t mode) {
	gcry_error_t err;

	if(!ciphertonid(&cipher->nid, algo, mode)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Cipher %d mode %d has no corresponding nid!", algo, mode);
		return false;
	}

	if((err = gcry_cipher_open(&cipher->handle, algo, mode, 0))) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unable to initialise cipher %d mode %d: %s", algo, mode, gcry_strerror(err));
		return false;
	}

	cipher->keylen = gcry_cipher_get_algo_keylen(algo);
	cipher->blklen = gcry_cipher_get_algo_blklen(algo);
	cipher->key = xmalloc(cipher_keylength(cipher));
	cipher->padding = mode == GCRY_CIPHER_MODE_ECB || mode == GCRY_CIPHER_MODE_CBC;

	return true;
}

bool cipher_open_by_name(cipher_t *cipher, const char *name) {
	cipher_algo_t algo;
	cipher_mode_t mode;

	if(!nametocipher(name, &algo, &mode)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown cipher name '%s'!", name);
		return false;
	}

	return cipher_open(cipher, algo, mode);
}

bool cipher_open_by_nid(cipher_t *cipher, nid_t nid) {
	cipher_algo_t algo;
	cipher_mode_t mode;

	if(!nidtocipher(&algo, &mode, nid)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown cipher ID %d!", nid);
		return false;
	}

	return cipher_open(cipher, algo, mode);
}

void cipher_close(cipher_t *cipher) {
	if(!cipher) {
		return;
	}

	if(cipher->handle) {
		gcry_cipher_close(cipher->handle);
	}

	xzfree(cipher->key, cipher_keylength(cipher));
	memset(cipher, 0, sizeof(*cipher));
}

size_t cipher_keylength(const cipher_t *cipher) {
	if(!cipher) {
		return 0;
	}

	return cipher->keylen + cipher->blklen;
}

uint64_t cipher_budget(const cipher_t *cipher) {
	if(!cipher) {
		return UINT64_MAX; // NULL cipher
	}

	size_t ivlen = cipher->blklen;
	size_t blklen = cipher->blklen;

	size_t len = blklen > 1
	             ? blklen
	             : ivlen > 1 ? ivlen : 8;
	size_t bits = len * 4 - 1;

	return bits < 64
	       ? UINT64_C(1) << bits
	       : UINT64_MAX;
}

size_t cipher_blocksize(const cipher_t *cipher) {
	if(!cipher || !cipher->blklen) {
		return 1;
	}

	return cipher->blklen;
}

bool cipher_set_key(cipher_t *cipher, void *key, bool encrypt) {
	(void)encrypt;

	memcpy(cipher->key, key, cipher_keylength(cipher));

	gcry_cipher_setkey(cipher->handle, cipher->key, cipher->keylen);
	gcry_cipher_setiv(cipher->handle, cipher->key + cipher->keylen, cipher->blklen);

	return true;
}

bool cipher_set_key_from_rsa(cipher_t *cipher, void *key, size_t len, bool encrypt) {
	(void)encrypt;

	memcpy(cipher->key, (char *)key + len - cipher->keylen, cipher->keylen);
	gcry_cipher_setkey(cipher->handle, cipher->key, cipher->keylen);

	memcpy((char *)cipher->key + cipher->keylen, (char *)key + len - cipher->blklen - cipher->keylen, cipher->blklen);
	gcry_cipher_setiv(cipher->handle, cipher->key + cipher->keylen, cipher->blklen);

	return true;
}

bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	gcry_error_t err;
	uint8_t *pad = alloca(cipher->blklen);

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
		if((err = gcry_cipher_encrypt(cipher->handle, (char *)outdata + inlen, cipher->blklen, pad, cipher->blklen))) {
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

		for(size_t i = inlen - 1; i >= origlen; i--)
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

nid_t cipher_get_nid(const cipher_t *cipher) {
	if(!cipher || !cipher->nid) {
		return 0;
	}

	return cipher->nid;
}

bool cipher_active(const cipher_t *cipher) {
	return cipher->nid != 0;
}
