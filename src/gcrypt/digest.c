/*
    digest.c -- Digest handling
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

#include "digest.h"
#include "../digest.h"
#include "../logger.h"

static struct {
	const char *name;
	md_algo_t algo;
	nid_t nid;
} digesttable[] = {
	{"none",   GCRY_MD_NONE,   0},
	{"sha1",   GCRY_MD_SHA1,   64},
	{"sha256", GCRY_MD_SHA256, 672},
	{"sha384", GCRY_MD_SHA384, 673},
	{"sha512", GCRY_MD_SHA512, 674},
};

static bool nametodigest(md_algo_t *algo, const char *name) {
	for(size_t i = 0; i < sizeof(digesttable) / sizeof(*digesttable); i++) {
		if(digesttable[i].name && !strcasecmp(name, digesttable[i].name)) {
			*algo = digesttable[i].algo;
			return true;
		}
	}

	return false;
}

static bool nidtodigest(md_algo_t *algo, nid_t nid) {
	for(size_t i = 0; i < sizeof(digesttable) / sizeof(*digesttable); i++) {
		if(nid == digesttable[i].nid) {
			*algo = digesttable[i].algo;
			return true;
		}
	}

	return false;
}

static bool digesttonid(nid_t *nid, md_algo_t algo) {
	for(size_t i = 0; i < sizeof(digesttable) / sizeof(*digesttable); i++) {
		if(algo == digesttable[i].algo) {
			*nid = digesttable[i].nid;
			return true;
		}
	}

	return false;
}

static bool digest_open(digest_t *digest, md_algo_t algo, size_t maclength) {
	if(!digesttonid(&digest->nid, algo)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Digest %d has no corresponding nid!", algo);
		return false;
	}

	unsigned int len = gcry_md_get_algo_dlen(algo);

	if(maclength > len) {
		digest->maclength = len;
	} else {
		digest->maclength = maclength;
	}

	digest->algo = algo;
	digest->hmac = NULL;

	return true;
}

bool digest_open_by_name(digest_t *digest, const char *name, size_t maclength) {
	md_algo_t algo;

	if(!nametodigest(&algo, name)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown digest name '%s'!", name);
		return false;
	}

	return digest_open(digest, algo, maclength);
}

bool digest_open_by_nid(digest_t *digest, nid_t nid, size_t maclength) {
	md_algo_t algo;

	if(!nidtodigest(&algo, nid)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Unknown digest ID %d!", nid);
		return false;
	}

	return digest_open(digest, algo, maclength);
}

void digest_close(digest_t *digest) {
	if(!digest) {
		return;
	}

	if(digest->hmac) {
		gcry_md_close(digest->hmac);
	}

	memset(digest, 0, sizeof(*digest));
}

bool digest_set_key(digest_t *digest, const void *key, size_t len) {
	if(!digest->hmac) {
		gcry_md_open(&digest->hmac, digest->algo, GCRY_MD_FLAG_HMAC);
	}

	if(!digest->hmac) {
		return false;
	}

	return !gcry_md_setkey(digest->hmac, key, len);
}

bool digest_create(digest_t *digest, const void *indata, size_t inlen, void *outdata) {
	unsigned int len = gcry_md_get_algo_dlen(digest->algo);

	if(digest->hmac) {
		uint8_t *tmpdata;
		gcry_md_reset(digest->hmac);
		gcry_md_write(digest->hmac, indata, inlen);
		tmpdata = gcry_md_read(digest->hmac, digest->algo);

		if(!tmpdata) {
			return false;
		}

		memcpy(outdata, tmpdata, digest->maclength);
	} else {
		char tmpdata[len];
		gcry_md_hash_buffer(digest->algo, tmpdata, indata, inlen);
		memcpy(outdata, tmpdata, digest->maclength);
	}

	return true;
}

bool digest_verify(digest_t *digest, const void *indata, size_t inlen, const void *cmpdata) {
	size_t len = digest->maclength;
	uint8_t outdata[len];

	return digest_create(digest, indata, inlen, outdata) && !memcmp(cmpdata, outdata, len);
}

nid_t digest_get_nid(const digest_t *digest) {
	if(!digest || !digest->nid) {
		return 0;
	}

	return digest->nid;
}

size_t digest_length(const digest_t *digest) {
	if(!digest) {
		return 0;
	}

	return digest->maclength;
}

bool digest_active(const digest_t *digest) {
	return digest && digest->algo != GCRY_MD_NONE;
}
