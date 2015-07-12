/*
    subnet.c -- handle subnet lookups and lists
    Copyright (C) 2000-2013 Guus Sliepen <guus@tinc-vpn.org>,
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
#include "device.h"
#include "hash.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "script.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

/* lists type of subnet */

splay_tree_t *subnet_tree;

/* Subnet lookup cache */

static hash_t *ipv4_cache;
static hash_t *ipv6_cache;
static hash_t *mac_cache;

void subnet_cache_flush(void) {
	hash_clear(ipv4_cache);
	hash_clear(ipv6_cache);
	hash_clear(mac_cache);
}

/* Initialising trees */

void init_subnets(void) {
	subnet_tree = splay_alloc_tree((splay_compare_t) subnet_compare, (splay_action_t) free_subnet);

	ipv4_cache = hash_alloc(0x100, sizeof(ipv4_t));
	ipv6_cache = hash_alloc(0x100, sizeof(ipv6_t));
	mac_cache = hash_alloc(0x100, sizeof(mac_t));
}

void exit_subnets(void) {
	splay_delete_tree(subnet_tree);

	hash_free(ipv4_cache);
	hash_free(ipv6_cache);
	hash_free(mac_cache);
}

splay_tree_t *new_subnet_tree(void) {
	return splay_alloc_tree((splay_compare_t) subnet_compare, NULL);
}

void free_subnet_tree(splay_tree_t *subnet_tree) {
	splay_delete_tree(subnet_tree);
}

/* Allocating and freeing space for subnets */

subnet_t *new_subnet(void) {
	return xzalloc(sizeof(subnet_t));
}

void free_subnet(subnet_t *subnet) {
	free(subnet);
}

/* Adding and removing subnets */

void subnet_add(node_t *n, subnet_t *subnet) {
	subnet->owner = n;

	splay_insert(subnet_tree, subnet);
	if (n)
		splay_insert(n->subnet_tree, subnet);

	subnet_cache_flush();
}

void subnet_del(node_t *n, subnet_t *subnet) {
	if (n)
		splay_delete(n->subnet_tree, subnet);
	splay_delete(subnet_tree, subnet);

	subnet_cache_flush();
}

/* Subnet lookup routines */

subnet_t *lookup_subnet(const node_t *owner, const subnet_t *subnet) {
	return splay_search(owner->subnet_tree, subnet);
}

subnet_t *lookup_subnet_mac(const node_t *owner, const mac_t *address) {
	subnet_t *r = NULL;

	// Check if this address is cached

	if((r = hash_search(mac_cache, address)))
		return r;

	// Search all subnets for a matching one

	for splay_each(subnet_t, p, owner ? owner->subnet_tree : subnet_tree) {
		if(!p || p->type != SUBNET_MAC)
			continue;

		if(!memcmp(address, &p->net.mac.address, sizeof *address)) {
			r = p;
			if(!p->owner || p->owner->status.reachable)
				break;
		}
	}

	// Cache the result

	if(r)
		hash_insert(mac_cache, address, r);

	return r;
}

subnet_t *lookup_subnet_ipv4(const ipv4_t *address) {
	subnet_t *r = NULL;

	// Check if this address is cached

	if((r = hash_search(ipv4_cache, address)))
		return r;

	// Search all subnets for a matching one

	for splay_each(subnet_t, p, subnet_tree) {
		if(!p || p->type != SUBNET_IPV4)
			continue;

		if(!maskcmp(address, &p->net.ipv4.address, p->net.ipv4.prefixlength)) {
			r = p;
			if(!p->owner || p->owner->status.reachable)
				break;
		}
	}

	// Cache the result

	if(r)
		hash_insert(ipv4_cache, address, r);

	return r;
}

subnet_t *lookup_subnet_ipv6(const ipv6_t *address) {
	subnet_t *r = NULL;

	// Check if this address is cached

	if((r = hash_search(ipv6_cache, address)))
		return r;

	// Search all subnets for a matching one

	for splay_each(subnet_t, p, subnet_tree) {
		if(!p || p->type != SUBNET_IPV6)
			continue;

		if(!maskcmp(address, &p->net.ipv6.address, p->net.ipv6.prefixlength)) {
			r = p;
			if(!p->owner || p->owner->status.reachable)
				break;
		}
	}

	// Cache the result

	if(r)
		hash_insert(ipv6_cache, address, r);

	return r;
}

void subnet_update(node_t *owner, subnet_t *subnet, bool up) {
	char netstr[MAXNETSTR];
	char *name, *address, *port;
	char empty[] = "";

	// Prepare environment variables to be passed to the script

	char *envp[10] = {NULL};
	int n = 0;
	xasprintf(&envp[n++], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[n++], "DEVICE=%s", device ? : "");
	xasprintf(&envp[n++], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[n++], "NODE=%s", owner->name);

	if(owner != myself) {
		sockaddr2str(&owner->address, &address, &port);
		xasprintf(&envp[n++], "REMOTEADDRESS=%s", address);
		xasprintf(&envp[n++], "REMOTEPORT=%s", port);
		free(port);
		free(address);
	}

	xasprintf(&envp[n++], "NAME=%s", myself->name);

	name = up ? "subnet-up" : "subnet-down";

	if(!subnet) {
		for splay_each(subnet_t, subnet, owner->subnet_tree) {
			if(!net2str(netstr, sizeof netstr, subnet))
				continue;

			// Strip the weight from the subnet, and put it in its own environment variable
			char *weight = strchr(netstr, '#');
			if(weight)
				*weight++ = 0;
			else
				weight = empty;

			// Prepare the SUBNET and WEIGHT variables
			free(envp[n]);
			free(envp[n + 1]);
			xasprintf(&envp[n], "SUBNET=%s", netstr);
			xasprintf(&envp[n + 1], "WEIGHT=%s", weight);

			execute_script(name, envp);
		}
	} else {
		if(net2str(netstr, sizeof netstr, subnet)) {
			// Strip the weight from the subnet, and put it in its own environment variable
			char *weight = strchr(netstr, '#');
			if(weight)
				*weight++ = 0;
			else
				weight = empty;

			// Prepare the SUBNET and WEIGHT variables
			xasprintf(&envp[n], "SUBNET=%s", netstr);
			xasprintf(&envp[n + 1], "WEIGHT=%s", weight);

			execute_script(name, envp);
		}
	}

	for(int i = 0; envp[i] && i < 9; i++)
		free(envp[i]);
}

bool dump_subnets(connection_t *c) {
	for splay_each(subnet_t, subnet, subnet_tree) {
		char netstr[MAXNETSTR];

		if(!net2str(netstr, sizeof netstr, subnet))
			continue;

		send_request(c, "%d %d %s %s",
				CONTROL, REQ_DUMP_SUBNETS,
				netstr, subnet->owner ? subnet->owner->name : "(broadcast)");
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_SUBNETS);
}
