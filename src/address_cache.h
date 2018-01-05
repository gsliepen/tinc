#ifndef TINC_ADDRESS_CACHE_H
#define TINC_ADDRESS_CACHE_H

/*
    address_cache.h -- header for address_cache.c
    Copyright (C) 2018 Guus Sliepen <guus@tinc-vpn.org>

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

#include "net.h"

#define MAX_CACHED_ADDRESSES 8
#define ADDRESS_CACHE_VERSION 1

typedef struct address_cache_t {
	struct node_t *node;
	struct splay_tree_t *config_tree;
	struct config_t *cfg;
	struct addrinfo *ai;
	struct addrinfo *aip;
	unsigned int tried;

	struct {
		unsigned int version;
		unsigned int used;
		sockaddr_t address[MAX_CACHED_ADDRESSES];
	} data;
} address_cache_t;

void add_recent_address(address_cache_t *cache, const sockaddr_t *sa);
const sockaddr_t *get_recent_address(address_cache_t *cache);

address_cache_t *open_address_cache(struct node_t *node);
void reset_address_cache(address_cache_t *cache, const sockaddr_t *sa);
void close_address_cache(address_cache_t *cache);

#endif
