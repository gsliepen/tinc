/*
    hash.h -- header file for hash.c
    Copyright (C) 2012 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_HASH_H__
#define __TINC_HASH_H__

typedef struct hash_t {
	size_t n;
	size_t size;
	char *keys;
	const void **values;
} hash_t;

extern hash_t *hash_alloc(size_t n, size_t size) __attribute__ ((__malloc__));
extern void hash_free(hash_t *);

extern void hash_insert(hash_t *, const void *key, const void *value);
extern void hash_delete(hash_t *, const void *key);

extern void *hash_search(const hash_t *, const void *key);
extern void *hash_search_or_insert(hash_t *, const void *key, const void *value);

extern void hash_clear(hash_t *);
extern void hash_resize(hash_t *, size_t n);

#endif /* __TINC_HASH_H__ */
