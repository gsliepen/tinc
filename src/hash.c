/*
    hash.c -- hash table management
    Copyright (C) 2012-2013 Guus Sliepen <guus@tinc-vpn.org>

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
			hash += (uint32_t)q[len - i] << (8 * i);
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
	hash_t *hash = xzalloc(sizeof *hash);
	hash->n = n;
	hash->size = size;
	hash->buckets = xzalloc(hash->n * sizeof *hash->buckets);
	return hash;
}

void hash_free(hash_t *hash) {
	hash_clear(hash);
	free(hash);
}

/* Searching and inserting */

static hash_node_t **hash_bucket(const hash_t *hash, const void *key) {
	return &hash->buckets[modulo(hash_function(key, hash->size), hash->n)];
}

static hash_node_t **hash_locate(const hash_t *hash, hash_node_t **node, const void *key) {
	while (*node && memcmp((*node)->key, key, hash->size))
		node = &(*node)->next;
	return node;
}

static void hash_add(const hash_t *hash, hash_node_t **bucket, const void *key, const void *value) {
	hash_node_t *node = xzalloc(sizeof *node);
	node->key = xmalloc(hash->size);
	memcpy(node->key, key, hash->size);
	node->value = value;

	node->next = *bucket;
	*bucket = node;
}

void hash_insert(hash_t *hash, const void *key, const void *value) {
	hash_add(hash, hash_bucket(hash, key), key, value);
}

void *hash_search(const hash_t *hash, const void *key) {
	hash_node_t *node = *hash_locate(hash, hash_bucket(hash, key), key);
	return node ? ((void*)node->value) : NULL;
}

void *hash_search_or_insert(hash_t *hash, const void *key, const void *value) {
	hash_node_t **bucket = hash_bucket(hash, key);
	hash_node_t *node = *hash_locate(hash, bucket, key);
	if (!node) {
		hash_add(hash, bucket, key, value);
		node = *bucket;
	}
	return (void *)node->value;
}

/* Deleting */

static void hash_delete_node(hash_node_t **node) {
	hash_node_t *next = (*node)->next;
	free((*node)->key);
	free(*node);
	*node = next;
}

void hash_delete(hash_t *hash, const void *key) {
	hash_node_t **node = hash_locate(hash, hash_bucket(hash, key), key);
	if (*node) hash_delete_node(node);
}

/* Utility functions */

void hash_clear(hash_t *hash) {
	for (size_t i = 0; i < hash->n; ++i) {
		hash_node_t **node = &hash->buckets[i];
		while (*node) hash_delete_node(node);
	}
}

