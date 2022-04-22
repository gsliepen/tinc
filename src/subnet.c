/*
    subnet.c -- handle subnet lookups and lists
    Copyright (C) 2000-2022 Guus Sliepen <guus@tinc-vpn.org>,
                  2000-2005 Ivo Timmermans

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

#include "splay_tree.h"
#include "control_common.h"
#include "crypto.h"
#include "hash.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "script.h"
#include "subnet.h"
#include "xalloc.h"
#include "sandbox.h"

/* lists type of subnet */
uint32_t hash_seed;
splay_tree_t subnet_tree = {
	.compare = (splay_compare_t) subnet_compare,
	.delete = (splay_action_t) free_subnet,
};

/* Subnet lookup cache */

static uint32_t wrapping_add32(uint32_t a, uint32_t b) {
	return (uint32_t)((uint64_t)a + b);
}

static uint32_t wrapping_mul32(uint32_t a, uint32_t b) {
	return (uint32_t)((uint64_t)a * b);
}

static uint32_t hash_function_ipv4_t(const ipv4_t *p) {
	/*
	This basic hash works because
	a) Most IPv4 networks routed via tinc are not /0
	b) Most IPv4 networks have more unique low order bits
	*/
	uint16_t *halfwidth = (uint16_t *)p;
	uint32_t hash = hash_seed;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	// 10.0.x.x/16 part
	hash = wrapping_add32(hash, wrapping_mul32(halfwidth[1], 0x9e370001U));

	// x.x.0.[0-255] part
#if SUBNET_HASH_SIZE >= 0x10000
	return hash ^ halfwidth[0];
#else
	// ensure that we have a /24 with no collisions on 32bit
	return hash ^ ntohs(halfwidth[0]);
#endif // _____LP64_____
#else
	// 10.0.x.x/16 part
	hash = wrapping_add32(hash, wrapping_mul32(halfwidth[0], 0x9e370001U));

	// x.x.0.[0-255] part (ntohs is nop on big endian)
	return hash ^ halfwidth[1];
#endif // __BYTE_ORDER == __LITTLE_ENDIAN
}


static uint32_t hash_function_ipv6_t(const ipv6_t *p) {
	uint32_t *fullwidth = (uint32_t *)p;
	uint32_t hash = hash_seed;

	for(int i = 0; i < 4; i++) {
		hash = wrapping_add32(hash, fullwidth[i]);
		hash = wrapping_mul32(hash, 0x9e370001U);
	}

	return hash;
}

static uint32_t hash_function_mac_t(const mac_t *p) {
	uint16_t *halfwidth = (uint16_t *)p;
	uint32_t hash = hash_seed;

	for(int i = 0; i < 3; i++) {
		hash = wrapping_add32(hash, halfwidth[i]);
		hash = wrapping_mul32(hash, 0x9e370001U);
	}

	return hash;
}

hash_define(ipv4_t, SUBNET_HASH_SIZE)
hash_define(ipv6_t, SUBNET_HASH_SIZE)
hash_define(mac_t, SUBNET_HASH_SIZE)

hash_new(ipv4_t, ipv4_cache);
hash_new(ipv6_t, ipv6_cache);
hash_new(mac_t, mac_cache);


void subnet_cache_flush_table(subnet_type_t stype) {
	// NOTE: a subnet type of SUBNET_TYPES can be used to clear all hash tables

	if(stype != SUBNET_IPV6) { // ipv4
		hash_clear(ipv4_t, &ipv4_cache);
	}

	if(stype != SUBNET_IPV4) { // ipv6
		hash_clear(ipv6_t, &ipv6_cache);
	}

	hash_clear(mac_t, &mac_cache);
}

/* Initialising trees */

void init_subnets(void) {
	hash_seed = prng(UINT32_MAX);

	// tables need to be cleared on startup
	subnet_cache_flush_tables();
}

void exit_subnets(void) {
	splay_empty_tree(&subnet_tree);
	subnet_cache_flush_tables();
}

void init_subnet_tree(splay_tree_t *tree) {
	memset(tree, 0, sizeof(*tree));
	tree->compare = (splay_compare_t) subnet_compare;
}

/* Allocating and freeing space for subnets */

subnet_t *new_subnet(void) {
	return xzalloc(sizeof(subnet_t));
}

void free_subnet(subnet_t *subnet) {
	free(subnet);
}

void subnet_cache_flush_tables(void) {
	// flushes all the tables
	hash_clear(ipv4_t, &ipv4_cache);
	hash_clear(ipv6_t, &ipv6_cache);
	hash_clear(mac_t, &mac_cache);
}

static void subnet_cache_flush(subnet_t *subnet) {
	switch(subnet->type) {
	case SUBNET_IPV4:
		if(subnet->net.ipv4.prefixlength == 32) {
			hash_delete(ipv4_t, &ipv4_cache, &subnet->net.ipv4.address);
			return;
		}

		break;

	case SUBNET_IPV6:
		if(subnet->net.ipv4.prefixlength == 128) {
			hash_delete(ipv6_t, &ipv6_cache, &subnet->net.ipv6.address);
			return;
		}

		break;

	case SUBNET_MAC:
		hash_delete(mac_t, &mac_cache, &subnet->net.mac.address);
		return;
	}

	subnet_cache_flush_table(subnet->type);
}

/* Adding and removing subnets */

void subnet_add(node_t *n, subnet_t *subnet) {
	subnet->owner = n;

	splay_insert(&subnet_tree, subnet);

	if(n) {
		splay_insert(&n->subnet_tree, subnet);
	}

	subnet_cache_flush(subnet);
}

void subnet_del(node_t *n, subnet_t *subnet) {
	if(n) {
		splay_delete(&n->subnet_tree, subnet);
	}

	splay_delete(&subnet_tree, subnet);

	subnet_cache_flush(subnet);
}

/* Subnet lookup routines */

subnet_t *lookup_subnet(node_t *owner, const subnet_t *subnet) {
	return splay_search(&owner->subnet_tree, subnet);
}

subnet_t *lookup_subnet_mac(const node_t *owner, const mac_t *address) {
	subnet_t *r = NULL;

	// Check if this address is cached

	if((r = hash_search(mac_t, &mac_cache, address))) {
		return r;
	}

	// Search all subnets for a matching one

	for splay_each(subnet_t, p, owner ? &owner->subnet_tree : &subnet_tree) {
		if(!p || p->type != SUBNET_MAC) {
			continue;
		}

		if(!memcmp(address, &p->net.mac.address, sizeof(*address))) {
			r = p;

			if(!p->owner || p->owner->status.reachable) {
				break;
			}
		}
	}

	// Cache the result

	if(r) {
		hash_insert(mac_t, &mac_cache, address, r);
	}

	return r;
}

subnet_t *lookup_subnet_ipv4(const ipv4_t *address) {
	subnet_t *r = NULL;

	// Check if this address is cached

	if((r = hash_search(ipv4_t, &ipv4_cache, address))) {
		return r;
	}

	// Search all subnets for a matching one

	for splay_each(subnet_t, p, &subnet_tree) {
		if(!p || p->type != SUBNET_IPV4) {
			continue;
		}

		if(!maskcmp(address, &p->net.ipv4.address, p->net.ipv4.prefixlength)) {
			r = p;

			if(!p->owner || p->owner->status.reachable) {
				break;
			}
		}
	}

	// Cache the result

	if(r) {
		hash_insert(ipv4_t, &ipv4_cache, address, r);
	}

	return r;
}

subnet_t *lookup_subnet_ipv6(const ipv6_t *address) {
	subnet_t *r = NULL;

	// Check if this address is cached

	if((r = hash_search(ipv6_t, &ipv6_cache, address))) {
		return r;
	}

	// Search all subnets for a matching one

	for splay_each(subnet_t, p, &subnet_tree) {
		if(!p || p->type != SUBNET_IPV6) {
			continue;
		}

		if(!maskcmp(address, &p->net.ipv6.address, p->net.ipv6.prefixlength)) {
			r = p;

			if(!p->owner || p->owner->status.reachable) {
				break;
			}
		}
	}

	// Cache the result

	if(r) {
		hash_insert(ipv6_t, &ipv6_cache, address, r);
	}

	return r;
}

void subnet_update(node_t *owner, subnet_t *subnet, bool up) {
	if(!sandbox_can(START_PROCESSES, RIGHT_NOW)) {
		return;
	}

	char netstr[MAXNETSTR];
	char *address, *port;
	char empty[] = "";

	// Prepare environment variables to be passed to the script

	environment_t env;
	environment_init(&env);
	environment_add(&env, "NODE=%s", owner->name);

	if(owner != myself) {
		sockaddr2str(&owner->address, &address, &port);
		environment_add(&env, "REMOTEADDRESS=%s", address);
		environment_add(&env, "REMOTEPORT=%s", port);
		free(port);
		free(address);
	}

	int env_subnet = environment_add(&env, NULL);
	int env_weight = environment_add(&env, NULL);

	const char *name = up ? "subnet-up" : "subnet-down";

	if(!subnet) {
		for splay_each(subnet_t, subnet, &owner->subnet_tree) {
			if(!net2str(netstr, sizeof(netstr), subnet)) {
				continue;
			}

			// Strip the weight from the subnet, and put it in its own environment variable
			char *weight = strchr(netstr, '#');

			if(weight) {
				*weight++ = 0;
			} else {
				weight = empty;
			}

			// Prepare the SUBNET and WEIGHT variables
			environment_update(&env, env_subnet, "SUBNET=%s", netstr);
			environment_update(&env, env_weight, "WEIGHT=%s", weight);

			execute_script(name, &env);
		}
	} else {
		if(net2str(netstr, sizeof(netstr), subnet)) {
			// Strip the weight from the subnet, and put it in its own environment variable
			char *weight = strchr(netstr, '#');

			if(weight) {
				*weight++ = 0;
			} else {
				weight = empty;
			}

			// Prepare the SUBNET and WEIGHT variables
			environment_update(&env, env_subnet, "SUBNET=%s", netstr);
			environment_update(&env, env_weight, "WEIGHT=%s", weight);

			execute_script(name, &env);
		}
	}

	environment_exit(&env);
}

bool dump_subnets(connection_t *c) {
	for splay_each(subnet_t, subnet, &subnet_tree) {
		char netstr[MAXNETSTR];

		if(!net2str(netstr, sizeof(netstr), subnet)) {
			continue;
		}

		send_request(c, "%d %d %s %s",
		             CONTROL, REQ_DUMP_SUBNETS,
		             netstr, subnet->owner ? subnet->owner->name : "(broadcast)");
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_SUBNETS);
}
