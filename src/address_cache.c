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
#include "hash.h"
#include "names.h"
#include "netutl.h"
#include "xalloc.h"

static const unsigned int NOT_CACHED = UINT_MAX;
#define RESOLVE_CACHE_SIZE 0x1000

typedef struct addrinfo_key_t {
	const char *address;
	const char *service;
	int socktype;
} addrinfo_key_t;

typedef struct addrinfo_result_t {
	addrinfo_key_t key;
    pthread_t tid;
    struct addrinfo *ai;
    int error;
} addrinfo_result_t;


static uint32_t hash_function_addrinfo_key_t(const addrinfo_key_t* key) {
	uint32_t hash = 0;
    const char* address = key->address;
    const char* service = key->service;
    int socktype = key->socktype;

    // Perform a simple hash calculation using XOR operations
    while (*address != '\0') {
        hash ^= *address;
        address++;
    }

    while (*service != '\0') {
        hash ^= *service;
        service++;
    }

    hash ^= socktype;

    return hash;
}

hash_define(addrinfo_key_t, RESOLVE_CACHE_SIZE)
hash_new(addrinfo_key_t, resolve_cache);

void *getaddrinfo_thread(void *arg) {
    struct addrinfo_result_t *result = (struct addrinfo_result_t *)arg;
    
    struct addrinfo *ai, hint = {0};
    int err;
    
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = result->key.socktype;
    
#if HAVE_DECL_RES_INIT
    res_init();
#endif
    err = getaddrinfo(result->key.address, result->key.service, &hint, &ai);
    
    result->error = err;
    result->ai = ai;
    
    return result;
}

/*
  Turn a string into a struct addrinfo.
  Return NULL on failure.
*/
struct addrinfo *resolve_str2addrinfo(const char *address, const char *service, int socktype) {
    struct timespec timeout;
	int join_result;
	addrinfo_key_t key;
	struct addrinfo *ai = NULL;
	struct addrinfo_result_t *r;
    
	// we will resolve this
	key.address = xstrdup(address);
	key.service = xstrdup(service);
	key.socktype = socktype;

	// check if we already have it
	r = hash_search(addrinfo_key_t, &resolve_cache, &key);
	if(r != NULL) {
		if(r->ai || r->error){
			if(r->error) {
				logger(DEBUG_ALWAYS, LOG_WARNING, "Error looking up %s port %s: %s", address, service, r->error == EAI_SYSTEM ? strerror(errno) : gai_strerror(r->error));
				freeaddrinfo(r->ai);
			}
			hash_delete(addrinfo_key_t, &resolve_cache, &key);
			ai = r->ai;
			goto free;
		} else {
			return NULL;
		}
	}

	// the job
    r = malloc(sizeof(struct addrinfo_result_t));
    if (r == NULL) {
        fprintf(stderr, "Failed to allocate memory for result\n");
        exit(EXIT_FAILURE);
    }

	// init result
	r->key = key;
	r->error = 0;
	r->ai = NULL;
    
	// the thread
    if (pthread_create(&r->tid, NULL, getaddrinfo_thread, (void *)r) != 0) {
        fprintf(stderr, "Failed to create pthread\n");
        exit(EXIT_FAILURE);
    }

    // wait 20ms (only)
    timeout.tv_sec = 0;
    timeout.tv_nsec = 20000000;
	join_result = pthread_timedjoin_np(r->tid, (void **)&r, &timeout);

	if (join_result == ETIMEDOUT) {
		hash_insert(addrinfo_key_t, &resolve_cache, &key, r);
		return NULL;
    }
	
	if (join_result != 0) {
        freeaddrinfo(result->ai);
		goto free;
    }
    
    if (r->error) {
        logger(DEBUG_ALWAYS, LOG_WARNING, "Error looking up %s port %s: %s", address, service, r->error == EAI_SYSTEM ? strerror(errno) : gai_strerror(r->error));
        freeaddrinfo(r->ai);
		goto free;
    }
    
   ai = r->ai;
free:
	free(r->key.address);
	free(r->key.service);
    free(r);
    return ai;
}

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
	if(!cache->config_tree) {
		cache->config_tree = create_configuration();
		read_host_config(cache->config_tree, cache->node->name, false);
		cache->cfg = lookup_config(cache->config_tree, "Address");
	}

	while(cache->cfg && !cache->aip) {
		char *address, *port;

		get_config_string(cache->cfg, &address);

		char *space = strchr(address, ' ');

		if(space) {
			port = xstrdup(space + 1);
			*space = 0;
		} else {
			if(!get_config_string(lookup_config(cache->config_tree, "Port"), &port)) {
				port = xstrdup("655");
			}
		}

		if(cache->ai) {
			free_known_addresses(cache->ai);
		}

		cache->aip = cache->ai = resolve_str2addrinfo(address, port, SOCK_STREAM);

		if(cache->ai) {
			struct addrinfo *ai = NULL;

			for(; cache->aip; cache->aip = cache->aip->ai_next) {
				struct addrinfo *oai = ai;

				ai = xzalloc(sizeof(*ai));
				ai->ai_family = cache->aip->ai_family;
				ai->ai_socktype = cache->aip->ai_socktype;
				ai->ai_protocol = cache->aip->ai_protocol;
				ai->ai_addrlen = cache->aip->ai_addrlen;
				ai->ai_addr = xmalloc(ai->ai_addrlen);
				memcpy(ai->ai_addr, cache->aip->ai_addr, ai->ai_addrlen);
				ai->ai_next = oai;
			}

			freeaddrinfo(cache->ai);
			cache->aip = cache->ai = ai;
		}

		free(address);
		free(port);

		cache->cfg = lookup_config_next(cache->config_tree, cache->cfg);
	}

	if(cache->ai) {
		if(cache->aip) {
			sockaddr_t *sa = (sockaddr_t *)cache->aip->ai_addr;

			cache->aip = cache->aip->ai_next;
			return sa;
		} else {
			free_known_addresses(cache->ai);
			cache->ai = NULL;
		}
	}

	// We're all out of addresses.
	exit_configuration(cache->config_tree);
	cache->config_tree = NULL;

	return NULL;
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
	cache->config_tree = NULL;
	cache->cfg = NULL;
	cache->ai = NULL;
	cache->aip = NULL;
	cache->tried = 0;
	cache->data.version = ADDRESS_CACHE_VERSION;

	if(cache->data.used > MAX_CACHED_ADDRESSES) {
		cache->data.used = 0;
	}

	return cache;
}

void reset_address_cache(address_cache_t *cache) {
	if(cache->config_tree) {
		exit_configuration(cache->config_tree);
		cache->config_tree = NULL;
	}

	if(cache->ai) {
		free_known_addresses(cache->ai);
	}

	cache->config_tree = NULL;
	cache->cfg = NULL;
	cache->ai = NULL;
	cache->aip = NULL;
	cache->tried = 0;
}

void close_address_cache(address_cache_t *cache) {
	if(cache->config_tree) {
		exit_configuration(cache->config_tree);
		cache->config_tree = NULL;
	}

	if(cache->ai) {
		free_known_addresses(cache->ai);
	}

	free(cache);
}
