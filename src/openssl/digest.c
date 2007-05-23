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

#include <openssl/err.h>

#include "digest.h"
#include "logger.h"

bool digest_open_by_name(digest_t *digest, const char *name) {
	digest->digest = EVP_get_digestbyname(name);
	if(digest->digest)
		return true;

	logger(LOG_DEBUG, _("Unknown digest name '%s'!"), name);
	return false;
}

bool digest_open_by_nid(digest_t *digest, int nid) {
	digest->digest = EVP_get_digestbynid(nid);
	if(digest->digest)
		return true;

	logger(LOG_DEBUG, _("Unknown digest nid %d!"), nid);
	return false;
}

bool digest_open_sha1(digest_t *digest) {
	digest->digest = EVP_sha1();
	return true;
}

void digest_close(digest_t *digest) {
}

bool digest_create(digest_t *digest, void *indata, size_t inlen, void *outdata) {
	EVP_MD_CTX ctx;

	if(EVP_DigestInit(&ctx, digest->digest)
			&& EVP_DigestUpdate(&ctx, indata, inlen)
			&& EVP_DigestFinal(&ctx, outdata, NULL))
		return true;
	
	logger(LOG_DEBUG, _("Error creating digest: %s"), ERR_error_string(ERR_get_error(), NULL));
	return false;
}

bool digest_verify(digest_t *digest, void *indata, size_t inlen, void *cmpdata) {
	size_t len = EVP_MD_size(digest->digest);
	char outdata[len];

	return digest_create(digest, indata, inlen, outdata) && !memcmp(cmpdata, outdata, len);
}

int digest_get_nid(const digest_t *digest) {
	return digest->digest ? digest->digest->type : 0;
}

size_t digest_length(const digest_t *digest) {
	return EVP_MD_size(digest->digest);
}

bool digest_active(const digest_t *digest) {
	return digest->digest && digest->digest->type != 0;
}
