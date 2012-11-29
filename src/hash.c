/*
    hash.c -- hash table management
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

#include "system.h"

#include "hash.h"
#include "xalloc.h"

/* Generic hash function */

static uint32_t hash_function(const void *p, size_t len) {
	const uint8_t *q = p;
	uint32_t hash = 0;
	while(true) {
		for(int i = len > 4 ? 4 : len; --i;)
			hash += q[i] << (8 * i);
		hash *= 0x9e370001UL; // Golden ratio prime.
		if(len <= 4)
			break;
		len -= 4;
	}
	return hash;
}

/* Map 32 bits int onto 0..n-1, without throwing away too many bits if n is 2^8 or 2^16 */

static uint32_t modulo(uint32_t hash, size_t n) {
	if(n == 0x100)
		return (hash >> 24) ^ ((hash >> 16) & 0xff) ^ ((hash >> 8) & 0xff) ^ (hash & 0xff);
	else if(n == 0x10000)
		return (hash >> 16) ^ (hash & 0xffff);
	else
		return hash % n;
}

/* (De)allocation */

hash_t *hash_alloc(size_t n, size_t size) {
	hash_t *hash = xmalloc_and_zero(sizeof *hash);
	hash->n = n;
	hash->size = size;
	hash->keys = xmalloc_and_zero(hash->n * hash->size);
	hash->values = xmalloc_and_zero(hash->n * sizeof *hash->values);
	return hash;
}

void hash_free(hash_t *hash) {
	free(hash->keys);
	free(hash->values);
	free(hash);
}

/* Searching and inserting */

void hash_insert(hash_t *hash, const void *key, const void *value) {
	uint32_t i = modulo(hash_function(key, hash->size), hash->n);
	memcpy(hash->keys + i * hash->size, key, hash->size);
	hash->values[i] = value;
}

void *hash_search(const hash_t *hash, const void *key) {
	uint32_t i = modulo(hash_function(key, hash->size), hash->n);
	if(hash->values[i] && !memcmp(key, hash->keys + i * hash->size, hash->size)) {
		return (void *)hash->values[i];
	}
	return NULL;
}

void *hash_search_or_insert(hash_t *hash, const void *key, const void *value) {
	uint32_t i = modulo(hash_function(key, hash->size), hash->n);
	if(hash->values[i] && !memcmp(key, hash->keys + i * hash->size, hash->size))
		return (void *)hash->values[i];
	memcpy(hash->keys + i * hash->size, key, hash->size);
	hash->values[i] = value;
	return NULL;
}

/* Utility functions */

void hash_clear(hash_t *hash) {
	memset(hash->values, 0, hash->n * sizeof *hash->values);
}

void hash_resize(hash_t *hash, size_t n) {
	hash->keys = xrealloc(hash->keys, n * hash->size);
	hash->values = xrealloc(hash->values, n * sizeof *hash->values);
	if(n > hash->n) {
		memset(hash->keys + hash->n * hash->size, 0, (n - hash->n) * hash->size);
		memset(hash->values + hash->n, 0, (n - hash->n) * sizeof *hash->values);
	}
}
