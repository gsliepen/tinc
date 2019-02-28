/*
    cipher.c -- Symmetric block cipher handling
    Copyright (C) 2007-2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../cipher.h"
#include "../logger.h"
#include "../xalloc.h"

struct cipher {
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
};

static cipher_t *cipher_open(const EVP_CIPHER *evp_cipher) {
	cipher_t *cipher = xzalloc(sizeof(*cipher));
	cipher->cipher = evp_cipher;
	cipher->ctx = EVP_CIPHER_CTX_new();

	if(!cipher->ctx) {
		abort();
	}

	return cipher;
}

cipher_t *cipher_open_by_name(const char *name) {
	const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname(name);

	if(!evp_cipher) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown cipher name '%s'!", name);
		return NULL;
	}

	return cipher_open(evp_cipher);
}

cipher_t *cipher_open_by_nid(int nid) {
	const EVP_CIPHER *evp_cipher = EVP_get_cipherbynid(nid);

	if(!evp_cipher) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown cipher nid %d!", nid);
		return NULL;
	}

	return cipher_open(evp_cipher);
}

void cipher_close(cipher_t *cipher) {
	if(!cipher) {
		return;
	}

	EVP_CIPHER_CTX_free(cipher->ctx);
	free(cipher);
}

size_t cipher_keylength(const cipher_t *cipher) {
	if(!cipher || !cipher->cipher) {
		return 0;
	}

	return EVP_CIPHER_key_length(cipher->cipher) + EVP_CIPHER_iv_length(cipher->cipher);
}

uint64_t cipher_budget(const cipher_t *cipher) {
	/* Hopefully some failsafe way to calculate the maximum amount of bytes to
	   send/receive with a given cipher before we might run into birthday paradox
	   attacks. Because we might use different modes, the block size of the mode
	   might be 1 byte. In that case, use the IV length. Ensure the whole thing
	   is limited to what can be represented with a 64 bits integer.
	 */

	if(!cipher || !cipher->cipher) {
		return UINT64_MAX;        // NULL cipher
	}

	int ivlen = EVP_CIPHER_iv_length(cipher->cipher);
	int blklen = EVP_CIPHER_block_size(cipher->cipher);
	int len = blklen > 1 ? blklen : ivlen > 1 ? ivlen : 8;
	int bits = len * 4 - 1;
	return bits < 64 ? UINT64_C(1) << bits : UINT64_MAX;
}

size_t cipher_blocksize(const cipher_t *cipher) {
	if(!cipher || !cipher->cipher) {
		return 1;
	}

	return EVP_CIPHER_block_size(cipher->cipher);
}

bool cipher_set_key(cipher_t *cipher, void *key, bool encrypt) {
	bool result;

	if(encrypt) {
		result = EVP_EncryptInit_ex(cipher->ctx, cipher->cipher, NULL, (unsigned char *)key, (unsigned char *)key + EVP_CIPHER_key_length(cipher->cipher));
	} else {
		result = EVP_DecryptInit_ex(cipher->ctx, cipher->cipher, NULL, (unsigned char *)key, (unsigned char *)key + EVP_CIPHER_key_length(cipher->cipher));
	}

	if(result) {
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while setting key: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_set_key_from_rsa(cipher_t *cipher, void *key, size_t len, bool encrypt) {
	bool result;

	if(encrypt) {
		result = EVP_EncryptInit_ex(cipher->ctx, cipher->cipher, NULL, (unsigned char *)key + len - EVP_CIPHER_key_length(cipher->cipher), (unsigned char *)key + len - EVP_CIPHER_iv_length(cipher->cipher) - EVP_CIPHER_key_length(cipher->cipher));
	} else {
		result = EVP_DecryptInit_ex(cipher->ctx, cipher->cipher, NULL, (unsigned char *)key + len - EVP_CIPHER_key_length(cipher->cipher), (unsigned char *)key + len - EVP_CIPHER_iv_length(cipher->cipher) - EVP_CIPHER_key_length(cipher->cipher));
	}

	if(result) {
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while setting key: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	if(oneshot) {
		int len, pad;

		if(EVP_EncryptInit_ex(cipher->ctx, NULL, NULL, NULL, NULL)
		                && EVP_EncryptUpdate(cipher->ctx, (unsigned char *)outdata, &len, indata, inlen)
		                && EVP_EncryptFinal_ex(cipher->ctx, (unsigned char *)outdata + len, &pad)) {
			if(outlen) {
				*outlen = len + pad;
			}

			return true;
		}
	} else {
		int len;

		if(EVP_EncryptUpdate(cipher->ctx, outdata, &len, indata, inlen)) {
			if(outlen) {
				*outlen = len;
			}

			return true;
		}
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool cipher_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) {
	if(oneshot) {
		int len, pad;

		if(EVP_DecryptInit_ex(cipher->ctx, NULL, NULL, NULL, NULL)
		                && EVP_DecryptUpdate(cipher->ctx, (unsigned char *)outdata, &len, indata, inlen)
		                && EVP_DecryptFinal_ex(cipher->ctx, (unsigned char *)outdata + len, &pad)) {
			if(outlen) {
				*outlen = len + pad;
			}

			return true;
		}
	} else {
		int len;

		if(EVP_DecryptUpdate(cipher->ctx, outdata, &len, indata, inlen)) {
			if(outlen) {
				*outlen = len;
			}

			return true;
		}
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: %s", ERR_error_string(ERR_get_error(), NULL));
	return false;
}

int cipher_get_nid(const cipher_t *cipher) {
	if(!cipher || !cipher->cipher) {
		return 0;
	}

	return EVP_CIPHER_nid(cipher->cipher);
}

bool cipher_active(const cipher_t *cipher) {
	return cipher && cipher->cipher && EVP_CIPHER_nid(cipher->cipher) != 0;
}
