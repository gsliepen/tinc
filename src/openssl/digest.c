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
#include "../utils.h"
#include "../xalloc.h"

#include <openssl/err.h>
#include <openssl/hmac.h>

#include "digest.h"
#include "../digest.h"
#include "../logger.h"

static digest_t *digest_open(const EVP_MD *evp_md, int maclength) {
	digest_t *digest = xzalloc(sizeof(*digest));
	digest->digest = evp_md;

	int digestlen = EVP_MD_size(digest->digest);

	if(maclength > digestlen || maclength < 0) {
		digest->maclength = digestlen;
	} else {
		digest->maclength = maclength;
	}

	return digest;
}

digest_t *digest_open_by_name(const char *name, int maclength) {
	const EVP_MD *evp_md = EVP_get_digestbyname(name);

	if(!evp_md) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown digest name '%s'!", name);
		return false;
	}

	return digest_open(evp_md, maclength);
}

digest_t *digest_open_by_nid(int nid, int maclength) {
	const EVP_MD *evp_md = EVP_get_digestbynid(nid);

	if(!evp_md) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown digest nid %d!", nid);
		return false;
	}

	return digest_open(evp_md, maclength);
}

bool digest_set_key(digest_t *digest, const void *key, size_t len) {
#ifdef HAVE_HMAC_CTX_NEW
	digest->hmac_ctx = HMAC_CTX_new();
	HMAC_Init_ex(digest->hmac_ctx, key, len, digest->digest, NULL);
#else
	digest->hmac_ctx = xzalloc(sizeof(*digest->hmac_ctx));
	HMAC_Init(digest->hmac_ctx, key, len, digest->digest);
#endif

	if(!digest->hmac_ctx) {
		abort();
	}

	return true;
}

void digest_close(digest_t *digest) {
	if(!digest) {
		return;
	}

	if(digest->md_ctx) {
		EVP_MD_CTX_destroy(digest->md_ctx);
	}

#ifdef HAVE_HMAC_CTX_NEW

	if(digest->hmac_ctx) {
		HMAC_CTX_free(digest->hmac_ctx);
	}

#else
	free(digest->hmac_ctx);
#endif

	free(digest);
}

bool digest_create(digest_t *digest, const void *indata, size_t inlen, void *outdata) {
	size_t len = EVP_MD_size(digest->digest);
	unsigned char tmpdata[len];

	if(digest->hmac_ctx) {
		if(!HMAC_Init_ex(digest->hmac_ctx, NULL, 0, NULL, NULL)
		                || !HMAC_Update(digest->hmac_ctx, indata, inlen)
		                || !HMAC_Final(digest->hmac_ctx, tmpdata, NULL)) {
			logger(DEBUG_ALWAYS, LOG_DEBUG, "Error creating digest: %s", ERR_error_string(ERR_get_error(), NULL));
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
			logger(DEBUG_ALWAYS, LOG_DEBUG, "Error creating digest: %s", ERR_error_string(ERR_get_error(), NULL));
			return false;
		}
	}

	memcpy(outdata, tmpdata, digest->maclength);
	return true;
}

bool digest_verify(digest_t *digest, const void *indata, size_t inlen, const void *cmpdata) {
	size_t len = digest->maclength;
	unsigned char outdata[len];

	return digest_create(digest, indata, inlen, outdata) && !memcmp(cmpdata, outdata, digest->maclength);
}

int digest_get_nid(const digest_t *digest) {
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
