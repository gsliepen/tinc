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


/* Map 32 bits int onto 0..n-1, without throwing away too many bits if n is 2^8 or 2^16 */

uint32_t modulo(uint32_t hash, size_t n);

#define hash_insert(t, ...) hash_insert_ ## t (__VA_ARGS__)
#define hash_delete(t, ...) hash_delete_ ## t (__VA_ARGS__)
#define hash_search(t, ...) hash_search_ ## t (__VA_ARGS__)
#define hash_search_or_insert(t, ...) hash_search_or_insert_ ## t (__VA_ARGS__)
#define hash_clear(t, n) hash_clear_ ## t ((n))

#define hash_define(t, n) \
	typedef struct hash_ ## t { \
		t keys[n]; \
		const void *values[n]; \
	} hash_ ## t; \
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
	void hash_insert_ ## t (hash_ ##t *hash, const void *key, const void *value) { \
		uint32_t i = modulo(hash_function_ ## t(key), n); \
		memcpy(hash->keys + i * sizeof(#t), key, sizeof(#t)); \
		hash->values[i] = value; \
	} \
	void *hash_search_ ## t (const hash_ ##t *hash, const void *key) { \
		uint32_t i = modulo(hash_function_ ## t(key), n); \
		if(hash->values[i] && !memcmp(key, hash->keys + i * sizeof(#t), sizeof(#t))) { \
			return (void *)hash->values[i]; \
		} \
		return NULL; \
	} \
	void *hash_search_or_insert_ ## t (hash_ ##t *hash, const void *key, const void *value) { \
		uint32_t i = modulo(hash_function_ ## t(key), n); \
		if(hash->values[i] && !memcmp(key, hash->keys + i * sizeof(#t), sizeof(#t))) { \
			return (void *)hash->values[i]; \
		} \
		memcpy(hash->keys + i * sizeof(#t), key, sizeof(#t)); \
		hash->values[i] = value; \
		return NULL; \
	} \
	void hash_delete_ ## t (hash_ ##t *hash, const void *key) { \
		uint32_t i = modulo(hash_function_ ## t(key), n); \
		hash->values[i] = NULL; \
	} \
	void hash_clear_ ## t(hash_ ##t *hash) { \
		memset(hash->values, 0, n * sizeof(*hash->values)); \
	}


#define hash_new(t, name) static hash_ ## t name

#endif
