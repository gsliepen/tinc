/*
    cipher.c -- Symmetric block cipher handling
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

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../cipher.h"
#include "../logger.h"
#include "../xalloc.h"

struct cipher {
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	struct cipher_counter *counter;
};

typedef struct cipher_counter {
	unsigned char counter[CIPHER_MAX_IV_SIZE];
	unsigned char block[CIPHER_MAX_IV_SIZE];
	int n;
} cipher_counter_t;

static cipher_t *cipher_open(const EVP_CIPHER *evp_cipher) {
	cipher_t *cipher = xzalloc(sizeof *cipher);
	cipher->cipher = evp_cipher;
	EVP_CIPHER_CTX_init(&cipher->ctx);

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

cipher_t *cipher_open_blowfish_ofb(void) {
	return cipher_open(EVP_bf_ofb());
}

void cipher_close(cipher_t *cipher) {
	if(!cipher)
		return;

	EVP_CIPHER_CTX_cleanup(&cipher->ctx);
	free(cipher->counter);
	free(cipher);
}

size_t cipher_keylength(const cipher_t *cipher) {
	if(!cipher || !cipher->cipher)
		return 0;

	return cipher->cipher->key_len + cipher->cipher->iv_len;
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
	if(len > cipher->cipher->iv_len - 4) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Counter too long");
		return false;
	}

	memcpy(cipher->counter->counter, counter, len);
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
		cipher->counter = xzalloc(sizeof *cipher->counter);
	else
		cipher->counter->n = 0;

	memcpy(cipher->counter->counter, (unsigned char *)key + cipher->cipher->key_len, cipher->cipher->iv_len);

	return true;
}

bool cipher_gcm_encrypt_start(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	int len = 0;
	if(!EVP_EncryptInit_ex(&cipher->ctx, NULL, NULL, NULL, cipher->counter->counter)
			|| (inlen && !EVP_EncryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, (unsigned char *)indata, inlen))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}
	if(outlen)
		*outlen = len;
	return true;
}

bool cipher_gcm_encrypt_finish(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	int len = 0, pad = 0;
	if((inlen && !EVP_EncryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, (unsigned char *)indata, inlen))
			|| !EVP_EncryptFinal(&cipher->ctx, (unsigned char *)outdata + len, &pad)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}
	EVP_CIPHER_CTX_ctrl(&cipher->ctx, EVP_CTRL_GCM_GET_TAG, 16, (unsigned char *)outdata + len + pad);
	if(outlen)
		*outlen = len + pad + 16;
	return true;
}

bool cipher_gcm_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	int len = 0, pad = 0;
	if(!EVP_EncryptInit_ex(&cipher->ctx, NULL, NULL, NULL, cipher->counter->counter) ||
			!EVP_EncryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, (unsigned char *)indata, inlen) ||
			!EVP_EncryptFinal(&cipher->ctx, (unsigned char *)outdata + len, &pad)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}
	EVP_CIPHER_CTX_ctrl(&cipher->ctx, EVP_CTRL_GCM_GET_TAG, 16, (unsigned char *)outdata + len + pad);
	if(outlen)
		*outlen = len + pad + 16;
	return true;
}

bool cipher_gcm_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	if(inlen < 16)
		return false;

	int len = 0, pad = 0;
	if(!EVP_DecryptInit_ex(&cipher->ctx, NULL, NULL, NULL, cipher->counter->counter)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	EVP_CIPHER_CTX_ctrl(&cipher->ctx, EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *)indata + inlen - 16);

	if(!EVP_DecryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, (unsigned char *)indata, inlen - 16) ||
			!EVP_DecryptFinal(&cipher->ctx, (unsigned char *)outdata + len, &pad)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}
	if(outlen)
		*outlen = len;
	return true;
}

bool cipher_gcm_decrypt_start(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	int len = 0;
	if(!EVP_DecryptInit_ex(&cipher->ctx, NULL, NULL, NULL, cipher->counter->counter)
			|| (inlen && !EVP_DecryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, (unsigned char *)indata, inlen))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}
	if(outlen)
		*outlen = len;
	return true;
}

bool cipher_gcm_decrypt_finish(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	if(inlen < 16)
		return false;

	EVP_CIPHER_CTX_ctrl(&cipher->ctx, EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *)indata + inlen - 16);

	int len = 0, pad = 0;
	if((inlen > 16 && !EVP_DecryptUpdate(&cipher->ctx, (unsigned char *)outdata, &len, (unsigned char *)indata, inlen - 16))
			|| !EVP_DecryptFinal(&cipher->ctx, (unsigned char *)outdata + len, &pad)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
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
	if(!cipher || !cipher->cipher)
		return 0;

	return cipher->cipher->nid;
}

bool cipher_active(const cipher_t *cipher) {
	return cipher && cipher->cipher && cipher->cipher->nid != 0;
}
