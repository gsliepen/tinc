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
	int i;

	for(i = 0; i < sizeof ciphertable / sizeof *ciphertable; i++) {
		if(ciphertable[i].name && !strcasecmp(name, ciphertable[i].name)) {
			*algo = ciphertable[i].algo;
			*mode = ciphertable[i].mode;
			return true;
		}
	}

	return false;
}

static bool nidtocipher(int nid, int *algo, int *mode) {
	int i;

	for(i = 0; i < sizeof ciphertable / sizeof *ciphertable; i++) {
		if(nid == ciphertable[i].nid) {
			*algo = ciphertable[i].algo;
			*mode = ciphertable[i].mode;
			return true;
		}
	}

	return false;
}

static bool ciphertonid(int algo, int mode, int *nid) {
	int i;

	for(i = 0; i < sizeof ciphertable / sizeof *ciphertable; i++) {
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
		logger(LOG_DEBUG, _("Cipher %d mode %d has no corresponding nid!"), algo, mode);
		return false;
	}

	if((err = gcry_cipher_open(&cipher->handle, algo, mode, 0))) {
		logger(LOG_DEBUG, _("Unable to intialise cipher %d mode %d: %s"), algo, mode, gcry_strerror(err));
		return false;
	}

	cipher->keylen = gcry_cipher_get_algo_keylen(algo);
	if(mode == GCRY_CIPHER_MODE_ECB || mode == GCRY_CIPHER_MODE_CBC)
		cipher->blklen = gcry_cipher_get_algo_blklen(algo);
	else
		cipher->blklen = 0;
	cipher->key = xmalloc(cipher->keylen + cipher->blklen);

	return true;
}

bool cipher_open_by_name(cipher_t *cipher, const char *name) {
	int algo, mode;

	if(!nametocipher(name, &algo, &mode)) {
		logger(LOG_DEBUG, _("Unknown cipher name '%s'!"), name);
		return false;
	}

	return cipher_open(cipher, algo, mode);
}

bool cipher_open_by_nid(cipher_t *cipher, int nid) {
	int algo, mode;

	if(!nidtocipher(nid, &algo, &mode)) {
		logger(LOG_DEBUG, _("Unknown cipher ID %d!"), nid);
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

static bool cipher_add_padding(cipher_t *cipher, void *indata, size_t inlen, size_t *outlen) {
	size_t reqlen;

	if(cipher->blklen == 1) {
		*outlen = inlen;
		return true;
	}

	reqlen = ((inlen + 1) / cipher->blklen) * cipher->blklen;
	if(reqlen > *outlen)
		return false;

	// add padding

	*outlen = reqlen;
	return true;
}

static bool cipher_remove_padding(cipher_t *cipher, void *indata, size_t inlen, size_t *outlen) {
	size_t origlen;

	if(cipher->blklen == 1) {
		*outlen = inlen;
		return true;
	}

	if(inlen % cipher->blklen)
		return false;

	// check and remove padding

	*outlen = origlen;
	return true;
}

bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	gcry_error_t err;

	// To be fixed

	if((err = gcry_cipher_encrypt(cipher->handle, outdata, inlen, indata, inlen))) {
		logger(LOG_ERR, _("Error while encrypting: %s"), gcry_strerror(err));
		return false;
	}

	return true;
}

bool cipher_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	gcry_error_t err;

	// To be fixed

	if((err = gcry_cipher_decrypt(cipher->handle, outdata, inlen, indata, inlen))) {
		logger(LOG_ERR, _("Error while decrypting: %s"), gcry_strerror(err));
		return false;
	}

	return true;
}

int cipher_get_nid(const cipher_t *cipher) {
	return cipher->nid;
}

bool cipher_active(const cipher_t *cipher) {
	return cipher->nid != 0;
}
