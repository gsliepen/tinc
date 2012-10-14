/*
    digest.h -- header file digest.c
    Copyright (C) 2007-2011 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_DIGEST_H__
#define __TINC_DIGEST_H__

#include <openssl/evp.h>

#define DIGEST_MAX_SIZE EVP_MAX_MD_SIZE

typedef struct digest {
	const EVP_MD *digest;
	int maclength;
	int keylength;
	char *key;
} digest_t;

extern bool digest_open_by_name(struct digest *, const char *name, int maclength);
extern bool digest_open_by_nid(struct digest *, int nid, int maclength);
extern bool digest_open_sha1(struct digest *, int maclength);
extern void digest_close(struct digest *);
extern bool digest_create(struct digest *, const void *indata, size_t inlen, void *outdata);
extern bool digest_verify(struct digest *, const void *indata, size_t inlen, const void *digestdata);
extern bool digest_set_key(struct digest *, const void *key, size_t len);
extern int digest_get_nid(const struct digest *);
extern size_t digest_keylength(const struct digest *);
extern size_t digest_length(const struct digest *);
extern bool digest_active(const struct digest *);

#endif
