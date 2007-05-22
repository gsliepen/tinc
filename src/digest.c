/*
    digest.c -- Digest handling
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

#include "digest.h"
#include "logger.h"

static struct {
	const char *name;
	int algo;
	int nid;
} digesttable[] = {
	{"none", GCRY_MD_NONE, 0},
	{"sha1", GCRY_MD_SHA1, 64},
	{"sha256", GCRY_MD_SHA256, 672},
	{"sha384", GCRY_MD_SHA384, 673},
	{"sha512", GCRY_MD_SHA512, 674},
};

static bool nametodigest(const char *name, int *algo) {
	int i;

	for(i = 0; i < sizeof digesttable / sizeof *digesttable; i++) {
		if(digesttable[i].name && !strcasecmp(name, digesttable[i].name)) {
			*algo = digesttable[i].algo;
			return true;
		}
	}

	return false;
}

static bool nidtodigest(int nid, int *algo) {
	int i;

	for(i = 0; i < sizeof digesttable / sizeof *digesttable; i++) {
		if(nid == digesttable[i].nid) {
			*algo = digesttable[i].algo;
			return true;
		}
	}

	return false;
}

static bool digesttonid(int algo, int *nid) {
	int i;

	for(i = 0; i < sizeof digesttable / sizeof *digesttable; i++) {
		if(algo == digesttable[i].algo) {
			*nid = digesttable[i].nid;
			return true;
		}
	}

	return false;
}

static bool digest_open(digest_t *digest, int algo) {
	if(!digesttonid(algo, &digest->nid)) {
		logger(LOG_DEBUG, _("Digest %d has no corresponding nid!"), algo);
		return false;
	}

	digest->len = gcry_md_get_algo_dlen(algo);

	return true;
}

bool digest_open_by_name(digest_t *digest, const char *name) {
	int algo;

	if(!nametodigest(name, &algo)) {
		logger(LOG_DEBUG, _("Unknown digest name '%s'!"), name);
		return false;
	}

	return digest_open(digest, algo);
}

bool digest_open_by_nid(digest_t *digest, int nid) {
	int algo;

	if(!nidtodigest(nid, &algo)) {
		logger(LOG_DEBUG, _("Unknown digest ID %d!"), nid);
		return false;
	}

	return digest_open(digest, algo);
}

bool digest_open_sha1(digest_t *digest) {
	return digest_open(digest, GCRY_MD_SHA1);
}

void digest_close(digest_t *digest) {
}

bool digest_create(digest_t *digest, void *indata, size_t inlen, void *outdata) {
	gcry_md_hash_buffer(digest->algo, outdata, indata, inlen);
	return true;
}

bool digest_verify(digest_t *digest, void *indata, size_t inlen, void *cmpdata) {
	char outdata[digest->len];

	gcry_md_hash_buffer(digest->algo, outdata, indata, inlen);
	return !memcmp(indata, outdata, digest->len);
}

int digest_get_nid(digest_t *digest) {
	return digest->nid;
}

