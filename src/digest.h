/*
    digest.h -- header file digest.c
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

#ifndef __TINC_DIGEST_H__
#define __TINC_DIGEST_H__

#define DIGEST_MAX_SIZE 64

#ifndef DISABLE_LEGACY

typedef struct digest digest_t;

extern digest_t *digest_open_by_name(const char *name, int maclength) __attribute__ ((__malloc__));
extern digest_t *digest_open_by_nid(int nid, int maclength) __attribute__ ((__malloc__));
extern void digest_close(digest_t *);
extern bool digest_create(digest_t *, const void *indata, size_t inlen, void *outdata) __attribute__ ((__warn_unused_result__));
extern bool digest_verify(digest_t *, const void *indata, size_t inlen, const void *digestdata) __attribute__ ((__warn_unused_result__));
extern bool digest_set_key(digest_t *, const void *key, size_t len) __attribute__ ((__warn_unused_result__));
extern int digest_get_nid(const digest_t *);
extern size_t digest_keylength(const digest_t *);
extern size_t digest_length(const digest_t *);
extern bool digest_active(const digest_t *);

#endif

#endif
