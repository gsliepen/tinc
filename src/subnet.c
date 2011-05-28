/*
    subnet.c -- handle subnet lookups and lists
    Copyright (C) 2000-2010 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "avl_tree.h"
#include "device.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "process.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

/* lists type of subnet */

avl_tree_t *subnet_tree;

/* Subnet lookup cache */

static ipv4_t cache_ipv4_address[2];
static subnet_t *cache_ipv4_subnet[2];
static bool cache_ipv4_valid[2];
static int cache_ipv4_slot;

static ipv6_t cache_ipv6_address[2];
static subnet_t *cache_ipv6_subnet[2];
static bool cache_ipv6_valid[2];
static int cache_ipv6_slot;

static mac_t cache_mac_address[2];
static subnet_t *cache_mac_subnet[2];
static bool cache_mac_valid[2];
static int cache_mac_slot;

void subnet_cache_flush(void) {
	cache_ipv4_valid[0] = cache_ipv4_valid[1] = false;
	cache_ipv6_valid[0] = cache_ipv6_valid[1] = false;
	cache_mac_valid[0] = cache_mac_valid[1] = false;
}

/* Subnet comparison */

static int subnet_compare_mac(const subnet_t *a, const subnet_t *b) {
	int result;

	result = memcmp(&a->net.mac.address, &b->net.mac.address, sizeof(mac_t));

	if(result)
		return result;
	
	result = a->weight - b->weight;

	if(result || !a->owner || !b->owner)
		return result;

	return strcmp(a->owner->name, b->owner->name);
}

static int subnet_compare_ipv4(const subnet_t *a, const subnet_t *b) {
	int result;

	result = b->net.ipv4.prefixlength - a->net.ipv4.prefixlength;

	if(result)
		return result;

	result = memcmp(&a->net.ipv4.address, &b->net.ipv4.address, sizeof(ipv4_t));

	if(result)
		return result;
	
	result = a->weight - b->weight;

	if(result || !a->owner || !b->owner)
		return result;

	return strcmp(a->owner->name, b->owner->name);
}

static int subnet_compare_ipv6(const subnet_t *a, const subnet_t *b) {
	int result;

	result = b->net.ipv6.prefixlength - a->net.ipv6.prefixlength;

	if(result)
		return result;
	
	result = memcmp(&a->net.ipv6.address, &b->net.ipv6.address, sizeof(ipv6_t));

	if(result)
		return result;
	
	result = a->weight - b->weight;

	if(result || !a->owner || !b->owner)
		return result;

	return strcmp(a->owner->name, b->owner->name);
}

int subnet_compare(const subnet_t *a, const subnet_t *b) {
	int result;

	result = a->type - b->type;

	if(result)
		return result;

	switch (a->type) {
	case SUBNET_MAC:
		return subnet_compare_mac(a, b);
	case SUBNET_IPV4:
		return subnet_compare_ipv4(a, b);
	case SUBNET_IPV6:
		return subnet_compare_ipv6(a, b);
	default:
		logger(LOG_ERR, "subnet_compare() was called with unknown subnet type %d, exitting!",
			   a->type);
		exit(0);
	}

	return 0;
}

/* Initialising trees */

void init_subnets(void) {
	subnet_tree = avl_alloc_tree((avl_compare_t) subnet_compare, (avl_action_t) free_subnet);

	subnet_cache_flush();
}

void exit_subnets(void) {
	avl_delete_tree(subnet_tree);
}

avl_tree_t *new_subnet_tree(void) {
	return avl_alloc_tree((avl_compare_t) subnet_compare, NULL);
}

void free_subnet_tree(avl_tree_t *subnet_tree) {
	avl_delete_tree(subnet_tree);
}

/* Allocating and freeing space for subnets */

subnet_t *new_subnet(void) {
	return xmalloc_and_zero(sizeof(subnet_t));
}

void free_subnet(subnet_t *subnet) {
	free(subnet);
}

/* Adding and removing subnets */

void subnet_add(node_t *n, subnet_t *subnet) {
	subnet->owner = n;

	avl_insert(subnet_tree, subnet);
	avl_insert(n->subnet_tree, subnet);

	subnet_cache_flush();
}

void subnet_del(node_t *n, subnet_t *subnet) {
	avl_delete(n->subnet_tree, subnet);
	avl_delete(subnet_tree, subnet);

	subnet_cache_flush();
}

/* Ascii representation of subnets */

bool str2net(subnet_t *subnet, const char *subnetstr) {
	int i, l;
	uint16_t x[8];
	int weight = 10;

	if(sscanf(subnetstr, "%hu.%hu.%hu.%hu/%d#%d",
			  &x[0], &x[1], &x[2], &x[3], &l, &weight) >= 5) {
		if(l < 0 || l > 32)
			return false;

		subnet->type = SUBNET_IPV4;
		subnet->net.ipv4.prefixlength = l;
		subnet->weight = weight;

		for(i = 0; i < 4; i++) {
			if(x[i] > 255)
				return false;
			subnet->net.ipv4.address.x[i] = x[i];
		}

		return true;
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d#%d",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7],
			  &l, &weight) >= 9) {
		if(l < 0 || l > 128)
			return false;

		subnet->type = SUBNET_IPV6;
		subnet->net.ipv6.prefixlength = l;
		subnet->weight = weight;

		for(i = 0; i < 8; i++)
			subnet->net.ipv6.address.x[i] = htons(x[i]);

		return true;
	}

	if(sscanf(subnetstr, "%hu.%hu.%hu.%hu#%d", &x[0], &x[1], &x[2], &x[3], &weight) >= 4) {
		subnet->type = SUBNET_IPV4;
		subnet->net.ipv4.prefixlength = 32;
		subnet->weight = weight;

		for(i = 0; i < 4; i++) {
			if(x[i] > 255)
				return false;
			subnet->net.ipv4.address.x[i] = x[i];
		}

		return true;
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx#%d",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7], &weight) >= 8) {
		subnet->type = SUBNET_IPV6;
		subnet->net.ipv6.prefixlength = 128;
		subnet->weight = weight;

		for(i = 0; i < 8; i++)
			subnet->net.ipv6.address.x[i] = htons(x[i]);

		return true;
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx#%d",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &weight) >= 6) {
		subnet->type = SUBNET_MAC;
		subnet->weight = weight;

		for(i = 0; i < 6; i++)
			subnet->net.mac.address.x[i] = x[i];

		return true;
	}

	return false;
}

bool net2str(char *netstr, int len, const subnet_t *subnet) {
	if(!netstr || !subnet) {
		logger(LOG_ERR, "net2str() was called with netstr=%p, subnet=%p!", netstr, subnet);
		return false;
	}

	switch (subnet->type) {
		case SUBNET_MAC:
			snprintf(netstr, len, "%hx:%hx:%hx:%hx:%hx:%hx#%d",
					 subnet->net.mac.address.x[0],
					 subnet->net.mac.address.x[1],
					 subnet->net.mac.address.x[2],
					 subnet->net.mac.address.x[3],
					 subnet->net.mac.address.x[4],
					 subnet->net.mac.address.x[5],
					 subnet->weight);
			break;

		case SUBNET_IPV4:
			snprintf(netstr, len, "%hu.%hu.%hu.%hu/%d#%d",
					 subnet->net.ipv4.address.x[0],
					 subnet->net.ipv4.address.x[1],
					 subnet->net.ipv4.address.x[2],
					 subnet->net.ipv4.address.x[3],
					 subnet->net.ipv4.prefixlength,
					 subnet->weight);
			break;

		case SUBNET_IPV6:
			snprintf(netstr, len, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d#%d",
					 ntohs(subnet->net.ipv6.address.x[0]),
					 ntohs(subnet->net.ipv6.address.x[1]),
					 ntohs(subnet->net.ipv6.address.x[2]),
					 ntohs(subnet->net.ipv6.address.x[3]),
					 ntohs(subnet->net.ipv6.address.x[4]),
					 ntohs(subnet->net.ipv6.address.x[5]),
					 ntohs(subnet->net.ipv6.address.x[6]),
					 ntohs(subnet->net.ipv6.address.x[7]),
					 subnet->net.ipv6.prefixlength,
					 subnet->weight);
			break;

		default:
			logger(LOG_ERR,
				   "net2str() was called with unknown subnet type %d, exiting!",
				   subnet->type);
			exit(0);
	}

	return true;
}

/* Subnet lookup routines */

subnet_t *lookup_subnet(const node_t *owner, const subnet_t *subnet) {
	return avl_search(owner->subnet_tree, subnet);
}

subnet_t *lookup_subnet_mac(const node_t *owner, const mac_t *address) {
	subnet_t *p, *r = NULL;
	avl_node_t *n;
	int i;

	// Check if this address is cached

	for(i = 0; i < 2; i++) {
		if(!cache_mac_valid[i])
			continue;
		if(owner && cache_mac_subnet[i] && cache_mac_subnet[i]->owner != owner)
			continue;
		if(!memcmp(address, &cache_mac_address[i], sizeof *address))
			return cache_mac_subnet[i];
	}

	// Search all subnets for a matching one

	for(n = owner ? owner->subnet_tree->head : subnet_tree->head; n; n = n->next) {
		p = n->data;
		
		if(!p || p->type != SUBNET_MAC)
			continue;

		if(!memcmp(address, &p->net.mac.address, sizeof *address)) {
			r = p;
			if(p->owner->status.reachable)
				break;
		}
	}

	// Cache the result

	cache_mac_slot = !cache_mac_slot;
	memcpy(&cache_mac_address[cache_mac_slot], address, sizeof *address);
	cache_mac_subnet[cache_mac_slot] = r;
	cache_mac_valid[cache_mac_slot] = true;

	return r;
}

subnet_t *lookup_subnet_ipv4(const ipv4_t *address) {
	subnet_t *p, *r = NULL;
	avl_node_t *n;
	int i;

	// Check if this address is cached

	for(i = 0; i < 2; i++) {
		if(!cache_ipv4_valid[i])
			continue;
		if(!memcmp(address, &cache_ipv4_address[i], sizeof *address))
			return cache_ipv4_subnet[i];
	}

	// Search all subnets for a matching one

	for(n = subnet_tree->head; n; n = n->next) {
		p = n->data;
		
		if(!p || p->type != SUBNET_IPV4)
			continue;

		if(!maskcmp(address, &p->net.ipv4.address, p->net.ipv4.prefixlength)) {
			r = p;
			if(p->owner->status.reachable)
				break;
		}
	}

	// Cache the result

	cache_ipv4_slot = !cache_ipv4_slot;
	memcpy(&cache_ipv4_address[cache_ipv4_slot], address, sizeof *address);
	cache_ipv4_subnet[cache_ipv4_slot] = r;
	cache_ipv4_valid[cache_ipv4_slot] = true;

	return r;
}

subnet_t *lookup_subnet_ipv6(const ipv6_t *address) {
	subnet_t *p, *r = NULL;
	avl_node_t *n;
	int i;

	// Check if this address is cached

	for(i = 0; i < 2; i++) {
		if(!cache_ipv6_valid[i])
			continue;
		if(!memcmp(address, &cache_ipv6_address[i], sizeof *address))
			return cache_ipv6_subnet[i];
	}

	// Search all subnets for a matching one

	for(n = subnet_tree->head; n; n = n->next) {
		p = n->data;
		
		if(!p || p->type != SUBNET_IPV6)
			continue;

		if(!maskcmp(address, &p->net.ipv6.address, p->net.ipv6.prefixlength)) {
			r = p;
			if(p->owner->status.reachable)
				break;
		}
	}

	// Cache the result

	cache_ipv6_slot = !cache_ipv6_slot;
	memcpy(&cache_ipv6_address[cache_ipv6_slot], address, sizeof *address);
	cache_ipv6_subnet[cache_ipv6_slot] = r;
	cache_ipv6_valid[cache_ipv6_slot] = true;

	return r;
}

void subnet_update(node_t *owner, subnet_t *subnet, bool up) {
	avl_node_t *node;
	int i;
	char *envp[9] = {NULL};
	char netstr[MAXNETSTR];
	char *name, *address, *port;
	char empty[] = "";

	// Prepare environment variables to be passed to the script

	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NODE=%s", owner->name);

	if(owner != myself) {
		sockaddr2str(&owner->address, &address, &port);
		// 4 and 5 are reserved for SUBNET and WEIGHT
		xasprintf(&envp[6], "REMOTEADDRESS=%s", address);
		xasprintf(&envp[7], "REMOTEPORT=%s", port);
	}

	name = up ? "subnet-up" : "subnet-down";

	if(!subnet) {
		for(node = owner->subnet_tree->head; node; node = node->next) {
			subnet = node->data;
			if(!net2str(netstr, sizeof netstr, subnet))
				continue;
			// Strip the weight from the subnet, and put it in its own environment variable
			char *weight = strchr(netstr, '#');
			if(weight)
				*weight++ = 0;
			else
				weight = empty;

			// Prepare the SUBNET and WEIGHT variables
			if(envp[4])
				free(envp[4]);
			if(envp[5])
				free(envp[5]);
			xasprintf(&envp[4], "SUBNET=%s", netstr);
			xasprintf(&envp[5], "WEIGHT=%s", weight);

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
			xasprintf(&envp[4], "SUBNET=%s", netstr);
			xasprintf(&envp[5], "WEIGHT=%s", weight);

			execute_script(name, envp);
		}
	}

	for(i = 0; envp[i] && i < 9; i++)
		free(envp[i]);
}

void dump_subnets(void) {
	char netstr[MAXNETSTR];
	subnet_t *subnet;
	avl_node_t *node;

	logger(LOG_DEBUG, "Subnet list:");

	for(node = subnet_tree->head; node; node = node->next) {
		subnet = node->data;
		if(!net2str(netstr, sizeof netstr, subnet))
			continue;
		logger(LOG_DEBUG, " %s owner %s", netstr, subnet->owner->name);
	}

	logger(LOG_DEBUG, "End of subnet list.");
}
