#ifndef TINC_HASH_H
#define TINC_HASH_H

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

typedef struct hash_t {
	size_t n;
	size_t size;
	char *keys;
	const void **values;
} hash_t;


/* Map 32 bits int onto 0..n-1, without throwing away too many bits if n is 2^8 or 2^16 */

uint32_t modulo(uint32_t hash, size_t n);

#define hash_insert(t, ...) hash_insert_ ## t (__VA_ARGS__)
#define hash_delete(t, ...) hash_delete_ ## t (__VA_ARGS__)
#define hash_search(t, ...) hash_search_ ## t (__VA_ARGS__)
#define hash_search_or_insert(t, ...) hash_search_or_insert_ ## t (__VA_ARGS__)

/* Generic hash functions */
extern void hash_free(hash_t *);
extern void hash_clear(hash_t *);
extern void hash_resize(hash_t *, size_t n);

#define hash_alloc_define(t) \
	static uint32_t hash_function_ ## t(const void *p) { \
		const uint8_t *q = p; \
		uint32_t hash = 0; \
		size_t len = sizeof(#t); \
		while(true) { \
			for(int i = len > 4 ? 4 : len; --i;) { \
				hash += (uint32_t)q[len - i] << (8 * i); \
			} \
			hash *= 0x9e370001UL; \
			if(len <= 4) break; \
			len -= 4; \
		} \
		return hash; \
	} \
	hash_t* hash_alloc_ ## t (size_t n) { \
		hash_t *hash = xzalloc(sizeof(*hash)); \
		hash->n = n; \
		hash->size = sizeof(#t); \
		hash->keys = xzalloc(hash->n * sizeof(#t)); \
		hash->values = xzalloc(hash->n * sizeof(*hash->values)); \
		return hash; \
	} \
	void hash_insert_ ## t (hash_t *hash, const void *key, const void *value) { \
		uint32_t i = modulo(hash_function_ ## t(key), hash->n); \
		memcpy(hash->keys + i * sizeof(#t), key, sizeof(#t)); \
		hash->values[i] = value; \
	} \
	void *hash_search_ ## t (const hash_t *hash, const void *key) { \
		uint32_t i = modulo(hash_function_ ## t(key), hash->n); \
		if(hash->values[i] && !memcmp(key, hash->keys + i * sizeof(#t), sizeof(#t))) { \
			return (void *)hash->values[i]; \
		} \
		return NULL; \
	} \
	void *hash_search_or_insert_ ## t (hash_t *hash, const void *key, const void *value) { \
		uint32_t i = modulo(hash_function_ ## t(key), hash->n); \
		if(hash->values[i] && !memcmp(key, hash->keys + i * sizeof(#t), sizeof(#t))) { \
			return (void *)hash->values[i]; \
		} \
		memcpy(hash->keys + i * sizeof(#t), key, sizeof(#t)); \
		hash->values[i] = value; \
		return NULL; \
	} \
	void hash_delete_ ## t (hash_t *hash, const void *key) { \
		uint32_t i = modulo(hash_function_ ## t(key), hash->n); \
		hash->values[i] = NULL; \
	}




#define hash_alloc(n, t) hash_alloc_ ## t ((n))

#endif
