/*
    digest.h -- header file digest.c
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

#ifndef __TINC_DIGEST_H__
#define __TINC_DIGEST_H__

#include <gcrypt.h>

typedef struct digest {
	enum gcry_md_algos algo;
	int nid;
	uint16_t len;
} digest_t;

bool digest_open_by_name(struct digest_t *, const char *);
bool digest_open_by_nid(struct digest_t *, int);
bool digest_open_sha1(struct digest_t *);
bool digest_create(struct digest_t *, void *indata, size_t inlen, void *outdata, size_t *outlen);
bool digest_verify(struct digest_t *, void *indata, size_t inlen, void *digestdata, size_t digestlen);
int digest_get_nid(struct digest_t *);

#endif
