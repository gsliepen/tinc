#ifndef TINC_HASH_H
#define TINC_HASH_H

/*
    hash.h -- header file for hash.c
    Copyright (C) 2012-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#define HASH_SEARCH_ITERATIONS 4

#define hash_insert(t, ...) hash_insert_ ## t (__VA_ARGS__)
#define hash_delete(t, ...) hash_delete_ ## t (__VA_ARGS__)
#define hash_search(t, ...) hash_search_ ## t (__VA_ARGS__)
#define hash_clear(t, n) hash_clear_ ## t ((n))

#define hash_define(t, n) \
	typedef struct hash_ ## t { \
		t keys[n]; \
		const void *values[n]; \
	} hash_ ## t; \
	static inline uint32_t hash_modulo_ ## t(uint32_t hash) { \
		return hash & (n - 1); \
	} \
	static inline void hash_insert_ ## t (hash_ ##t *hash, const t *key, const void *value) { \
		uint32_t i = hash_modulo_ ## t(hash_function_ ## t(key)); \
		for(uint8_t f=0; f< (HASH_SEARCH_ITERATIONS - 1); f++){ \
			if(hash->values[i] == NULL || !memcmp(key, &hash->keys[i], sizeof(t))) { \
				memcpy(&hash->keys[i], key, sizeof(t)); \
				hash->values[i] = value; \
				return; \
			} \
			if(++i == n) i = 0; \
		} \
		/* We always pick the last slot. It's unfair. But thats life */ \
		memcpy(&hash->keys[i], key, sizeof(t)); \
		hash->values[i] = value; \
	} \
	static inline void *hash_search_ ## t (const hash_ ##t *hash, const t *key) { \
		uint32_t i = hash_modulo_ ## t(hash_function_ ## t(key)); \
		for(uint8_t f=0; f<HASH_SEARCH_ITERATIONS; f++){ \
			if(!memcmp(key, &hash->keys[i], sizeof(t))) { \
				return (void *)hash->values[i]; \
			} \
			if(++i == n) i = 0; \
		} \
		return NULL; \
	} \
	static inline void hash_delete_ ## t (hash_ ##t *hash, const t *key) { \
		uint32_t i = hash_modulo_ ## t(hash_function_ ## t(key)); \
		for(uint8_t f=0; f<HASH_SEARCH_ITERATIONS; f++){ \
			if(!memcmp(key, &hash->keys[i], sizeof(t))) { \
				hash->values[i] = NULL; \
				return; \
			} \
			if(++i == n) i = 0; \
		} \
	} \
	static inline void hash_clear_ ## t(hash_ ##t *hash) { \
		memset(hash->values, 0, n * sizeof(*hash->values)); \
		memset(hash->keys, 0, n * sizeof(*hash->keys)); \
	}


#define hash_new(t, name) static hash_ ## t name

#endif
