/*
    address_cache.c -- Manage cache of recently seen addresses
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

#include "system.h"

#include "address_cache.h"
#include "conf.h"
#include "names.h"
#include "netutl.h"
#include "resolver.h"
#include "xalloc.h"

static const unsigned int NOT_CACHED = UINT_MAX;

// Find edges pointing to this node, and use them to build a list of unique, known addresses.
static struct addrinfo *get_known_addresses(node_t *n) {
	struct addrinfo *ai = NULL;
	struct addrinfo *oai = NULL;

	for splay_each(edge_t, e, &n->edge_tree) {
		if(!e->reverse) {
			continue;
		}

		bool found = false;

		for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
			if(!sockaddrcmp(&e->reverse->address, (sockaddr_t *)aip->ai_addr)) {
				found = true;
				break;
			}
		}

		if(found) {
			continue;
		}

		oai = ai;
		ai = xzalloc(sizeof(*ai));
		ai->ai_family = e->reverse->address.sa.sa_family;
		ai->ai_socktype = SOCK_STREAM;
		ai->ai_protocol = IPPROTO_TCP;
		ai->ai_addrlen = SALEN(e->reverse->address.sa);
		ai->ai_addr = xmalloc(ai->ai_addrlen);
		memcpy(ai->ai_addr, &e->reverse->address, ai->ai_addrlen);
		ai->ai_next = oai;
	}

	return ai;
}

static void free_known_addresses(struct addrinfo *ai) {
	for(struct addrinfo *aip = ai, *next; aip; aip = next) {
		next = aip->ai_next;
		free(aip->ai_addr);
		free(aip);
	}
}

static unsigned int find_cached(address_cache_t *cache, const sockaddr_t *sa) {
	for(unsigned int i = 0; i < cache->data.used; i++)
		if(!sockaddrcmp(&cache->data.address[i], sa)) {
			return i;
		}

	return NOT_CACHED;
}

void add_recent_address(address_cache_t *cache, const sockaddr_t *sa) {
	// Check if it's already cached
	unsigned int pos = find_cached(cache, sa);

	// It's in the first spot, so nothing to do
	if(pos == 0) {
		return;
	}

	logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Caching recent address for %s", cache->node->name);

	// Shift everything, move/add the address to the first slot
	if(pos == NOT_CACHED) {
		if(cache->data.used < MAX_CACHED_ADDRESSES) {
			cache->data.used++;
		}

		pos = cache->data.used - 1;
	}

	memmove(&cache->data.address[1], &cache->data.address[0], pos * sizeof(cache->data.address[0]));

	cache->data.address[0] = *sa;

	// Write the cache
	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "cache" SLASH "%s", confbase, cache->node->name);
	FILE *fp = fopen(fname, "wb");

	if(fp) {
		fwrite(&cache->data, sizeof(cache->data), 1, fp);
		fclose(fp);
	}
}

// Turn the result of getaddrinfo() into a list that free_known_addresses() can free.
static struct addrinfo *copy_addrinfo(struct addrinfo *result) {
	struct addrinfo *ai = NULL;

	for(struct addrinfo *aip = result; aip; aip = aip->ai_next) {
		struct addrinfo *oai = ai;

		ai = xzalloc(sizeof(*ai));
		ai->ai_family = aip->ai_family;
		ai->ai_socktype = aip->ai_socktype;
		ai->ai_protocol = aip->ai_protocol;
		ai->ai_addrlen = aip->ai_addrlen;
		ai->ai_addr = xmalloc(ai->ai_addrlen);
		memcpy(ai->ai_addr, aip->ai_addr, ai->ai_addrlen);
		ai->ai_next = oai;
	}

	freeaddrinfo(result);
	return ai;
}

static void address_resolved(void *data, struct addrinfo *ai) {
	address_lookup_t *lookup = data;
	address_cache_t *cache = lookup->cache;

	lookup->request = NULL;
	lookup->ai = ai ? copy_addrinfo(ai) : NULL;

	// Addresses are tried in the order of the Address statements, so only the next one can unblock a connection attempt.
	if(cache->waiting && lookup == &cache->lookups[cache->next_lookup]) {
		cache->waiting = false;
		retry_outgoing_now(cache->node);
	}
}

static void split_address(splay_tree_t *config_tree, const config_t *cfg, char **address, char **port) {
	get_config_string(cfg, address);

	char *space = strchr(*address, ' ');

	if(space) {
		*port = xstrdup(space + 1);
		*space = 0;
	} else if(!get_config_string(lookup_config(config_tree, "Port"), port)) {
		*port = xstrdup("655");
	}
}

// Resolve all Address statements at once, so that the total delay is that of the slowest one rather than their sum.
static void start_lookups(address_cache_t *cache) {
	splay_tree_t *config_tree = create_configuration();
	read_host_config(config_tree, cache->node->name, false);

	for(config_t *cfg = lookup_config(config_tree, "Address"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		cache->lookup_count++;
	}

	// One spare entry, since calloc() may fail for zero bytes.
	cache->lookups = xzalloc((cache->lookup_count + 1) * sizeof(*cache->lookups));
	address_lookup_t *lookup = cache->lookups;

	for(config_t *cfg = lookup_config(config_tree, "Address"); cfg; cfg = lookup_config_next(config_tree, cfg), lookup++) {
		char *address, *port;
		split_address(config_tree, cfg, &address, &port);

		lookup->cache = cache;
		struct addrinfo *ai = resolve_numeric(address, port, SOCK_STREAM);

		if(ai) {
			lookup->ai = copy_addrinfo(ai);
		} else {
			lookup->request = resolve_start(address, port, SOCK_STREAM, address_resolved, lookup);
		}

		free(address);
		free(port);
	}

	exit_configuration(config_tree);
}

static void stop_lookups(address_cache_t *cache) {
	for(unsigned int i = 0; i < cache->lookup_count; i++) {
		address_lookup_t *lookup = &cache->lookups[i];

		if(lookup->request) {
			resolve_cancel(lookup->request);
		}

		if(lookup->ai) {
			free_known_addresses(lookup->ai);
		}
	}

	free(cache->lookups);
	cache->lookups = NULL;
	cache->lookup_count = 0;
	cache->next_lookup = 0;
	cache->waiting = false;
}

const sockaddr_t *get_recent_address(address_cache_t *cache) {
	// Check if there is an address in our cache of recently seen addresses
	if(cache->tried < cache->data.used) {
		return &cache->data.address[cache->tried++];
	}

	// Next, check any recently seen addresses not in our cache
	while(cache->tried == cache->data.used) {
		if(!cache->ai) {
			cache->aip = cache->ai = get_known_addresses(cache->node);
		}

		if(cache->ai) {
			if(cache->aip) {
				sockaddr_t *sa = (sockaddr_t *)cache->aip->ai_addr;
				cache->aip = cache->aip->ai_next;

				if(find_cached(cache, sa) != NOT_CACHED) {
					continue;
				}

				return sa;
			} else {
				free_known_addresses(cache->ai);
				cache->ai = NULL;
			}
		}

		cache->tried++;
	}

	// Otherwise, check if there are any known Address statements
	if(!cache->lookups) {
		start_lookups(cache);
	}

	while(!cache->aip) {
		if(cache->ai) {
			free_known_addresses(cache->ai);
			cache->ai = NULL;
		}

		if(cache->next_lookup == cache->lookup_count) {
			// We're all out of addresses.
			stop_lookups(cache);
			return NULL;
		}

		address_lookup_t *lookup = &cache->lookups[cache->next_lookup];

		if(lookup->request) {
			cache->waiting = true;
			return NULL;
		}

		cache->aip = cache->ai = lookup->ai;
		lookup->ai = NULL;
		cache->next_lookup++;
	}

	sockaddr_t *sa = (sockaddr_t *)cache->aip->ai_addr;
	cache->aip = cache->aip->ai_next;
	return sa;
}

address_cache_t *open_address_cache(node_t *node) {
	address_cache_t *cache = xmalloc(sizeof(*cache));
	cache->node = node;

	// Try to open an existing address cache
	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "cache" SLASH "%s", confbase, node->name);
	FILE *fp = fopen(fname, "rb");

	if(!fp || fread(&cache->data, sizeof(cache->data), 1, fp) != 1 || cache->data.version != ADDRESS_CACHE_VERSION) {
		memset(&cache->data, 0, sizeof(cache->data));
	}

	if(fp) {
		fclose(fp);
	}

	// Ensure we have a valid state
	cache->ai = NULL;
	cache->aip = NULL;
	cache->lookups = NULL;
	cache->lookup_count = 0;
	cache->next_lookup = 0;
	cache->waiting = false;
	cache->tried = 0;
	cache->data.version = ADDRESS_CACHE_VERSION;

	if(cache->data.used > MAX_CACHED_ADDRESSES) {
		cache->data.used = 0;
	}

	return cache;
}

void reset_address_cache(address_cache_t *cache) {
	stop_lookups(cache);

	if(cache->ai) {
		free_known_addresses(cache->ai);
	}

	cache->ai = NULL;
	cache->aip = NULL;
	cache->tried = 0;
}

void close_address_cache(address_cache_t *cache) {
	stop_lookups(cache);

	if(cache->ai) {
		free_known_addresses(cache->ai);
	}

	free(cache);
}
