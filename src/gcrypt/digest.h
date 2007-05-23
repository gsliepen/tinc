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
	int algo;
	int nid;
	uint16_t len;
} digest_t;

static bool digest_open_by_name(struct digest *, const char *);
static bool digest_open_by_nid(struct digest *, int);
static bool digest_open_sha1(struct digest *);
static void digest_close(struct digest *);
static bool digest_create(struct digest *, const void *indata, size_t inlen, void *outdata);
static bool digest_verify(struct digest *, const void *indata, size_t inlen, const void *digestdata);
static int digest_get_nid(const struct digest *);
static size_t digest_length(const struct digest *);
static bool digest_active(const struct digest *);

#endif
