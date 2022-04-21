/*
    digest.c -- Digest handling
    Copyright (C) 2007-2016 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/err.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core_names.h>
#endif

#include "digest.h"
#include "../digest.h"
#include "../logger.h"
#include "log.h"

static void digest_open(digest_t *digest, const EVP_MD *evp_md, size_t maclength) {
	digest->digest = evp_md;

	size_t digestlen = EVP_MD_size(digest->digest);

	if(maclength == DIGEST_ALGO_SIZE || maclength > digestlen) {
		digest->maclength = digestlen;
	} else {
		digest->maclength = maclength;
	}
}

bool digest_open_by_name(digest_t *digest, const char *name, size_t maclength) {
	const EVP_MD *evp_md = EVP_get_digestbyname(name);

	if(!evp_md) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown digest name '%s'!", name);
		return false;
	}

	digest_open(digest, evp_md, maclength);
	return true;
}

bool digest_open_by_nid(digest_t *digest, nid_t nid, size_t maclength) {
	const EVP_MD *evp_md = EVP_get_digestbynid(nid);

	if(!evp_md) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown digest nid %d!", nid);
		return false;
	}

	digest_open(digest, evp_md, maclength);
	return true;
}

bool digest_set_key(digest_t *digest, const void *key, size_t len) {
#if OPENSSL_VERSION_MAJOR < 3
	digest->hmac_ctx = HMAC_CTX_new();

	if(!digest->hmac_ctx) {
		abort();
	}

	HMAC_Init_ex(digest->hmac_ctx, key, (int)len, digest->digest, NULL);
#else
	EVP_MAC *mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);

	if(!mac) {
		openssl_err("fetch MAC");
		return false;
	}

	digest->hmac_ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);

	if(!digest->hmac_ctx) {
		openssl_err("create MAC context");
		return false;
	}

	const char *hmac_algo = EVP_MD_get0_name(digest->digest);

	if(!hmac_algo) {
		openssl_err("get HMAC algorithm name");
		return false;
	}

	// The casts are okay, the parameters are not going to change. For example, see:
	// https://github.com/openssl/openssl/blob/31b7f23d2f958491d46c8a8e61c2b77b1b546f3e/crypto/ec/ecdh_kdf.c#L37-L38
	const OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, (void *)key, len),
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, (void *)hmac_algo, 0),
		OSSL_PARAM_END,
	};

	if(!EVP_MAC_init(digest->hmac_ctx, NULL, 0, params)) {
		openssl_err("set MAC context params");
		return false;
	}

#endif
	return true;
}

void digest_close(digest_t *digest) {
	if(!digest) {
		return;
	}

	if(digest->md_ctx) {
		EVP_MD_CTX_destroy(digest->md_ctx);
	}

	if(digest->hmac_ctx) {
#if OPENSSL_VERSION_MAJOR < 3
		HMAC_CTX_free(digest->hmac_ctx);
#else
		EVP_MAC_CTX_free(digest->hmac_ctx);
#endif
	}

	memset(digest, 0, sizeof(*digest));
}

bool digest_create(digest_t *digest, const void *indata, size_t inlen, void *outdata) {
	size_t len = EVP_MD_size(digest->digest);
	unsigned char *tmpdata = alloca(len);

	if(digest->hmac_ctx) {
		bool ok;

#if OPENSSL_VERSION_MAJOR < 3
		ok = HMAC_Init_ex(digest->hmac_ctx, NULL, 0, NULL, NULL)
		     && HMAC_Update(digest->hmac_ctx, indata, inlen)
		     && HMAC_Final(digest->hmac_ctx, tmpdata, NULL);
#else
		EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_dup(digest->hmac_ctx);

		ok = mac_ctx
		     && EVP_MAC_update(mac_ctx, indata, inlen)
		     && EVP_MAC_final(mac_ctx, tmpdata, NULL, len);

		EVP_MAC_CTX_free(mac_ctx);
#endif

		if(!ok) {
			openssl_err("create HMAC");
			return false;
		}
	} else {
		if(!digest->md_ctx) {
			digest->md_ctx = EVP_MD_CTX_create();
		}

		if(!digest->md_ctx) {
			abort();
		}

		if(!EVP_DigestInit(digest->md_ctx, digest->digest)
		                || !EVP_DigestUpdate(digest->md_ctx, indata, inlen)
		                || !EVP_DigestFinal(digest->md_ctx, tmpdata, NULL)) {
			openssl_err("create digest");
			return false;
		}
	}

	memcpy(outdata, tmpdata, digest->maclength);
	return true;
}

bool digest_verify(digest_t *digest, const void *indata, size_t inlen, const void *cmpdata) {
	size_t len = digest->maclength;
	unsigned char *outdata = alloca(len);

	return digest_create(digest, indata, inlen, outdata) && !memcmp(cmpdata, outdata, digest->maclength);
}

nid_t digest_get_nid(const digest_t *digest) {
	if(!digest || !digest->digest) {
		return 0;
	}

	return EVP_MD_type(digest->digest);
}

size_t digest_keylength(const digest_t *digest) {
	if(!digest || !digest->digest) {
		return 0;
	}

	return EVP_MD_size(digest->digest);
}

size_t digest_length(const digest_t *digest) {
	if(!digest) {
		return 0;
	}

	return digest->maclength;
}

bool digest_active(const digest_t *digest) {
	return digest && digest->digest && EVP_MD_type(digest->digest) != 0;
}
