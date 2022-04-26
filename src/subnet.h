#ifndef TINC_SUBNET_H
#define TINC_SUBNET_H

/*
    subnet.h -- header for subnet.c
    Copyright (C) 2000-2021 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "net.h"
#include "node.h"

typedef enum subnet_type_t {
	SUBNET_MAC = 0,
	SUBNET_IPV4,
	SUBNET_IPV6
} subnet_type_t;

typedef struct subnet_mac_t {
	mac_t address;
} subnet_mac_t;

typedef struct subnet_ipv4_t {
	int prefixlength;
	ipv4_t address;
} subnet_ipv4_t;

typedef struct subnet_ipv6_t {
	int prefixlength;
	ipv6_t address;
} subnet_ipv6_t;

typedef struct subnet_t {
	struct node_t *owner;   /* the owner of this subnet */

	subnet_type_t type;     /* subnet type (IPv4? IPv6? MAC? something even weirder?) */
	time_t expires;         /* expiry time */
	int weight;             /* weight (higher value is higher priority) */

	/* And now for the actual subnet: */

	union net {
		subnet_mac_t mac;
		subnet_ipv4_t ipv4;
		subnet_ipv6_t ipv6;
	} net;
} subnet_t;

#define MAXNETSTR 64

extern splay_tree_t subnet_tree;

extern int subnet_compare(const struct subnet_t *a, const struct subnet_t *b);
extern void free_subnet(subnet_t *subnet);
extern subnet_t *new_subnet(void) ATTR_MALLOC ATTR_DEALLOCATOR(free_subnet);
extern void init_subnets(void);
extern void exit_subnets(void);
extern void init_subnet_tree(splay_tree_t *tree);
extern void subnet_add(struct node_t *owner, subnet_t *subnet);
extern void subnet_del(struct node_t *owner, subnet_t *subnet);
extern void subnet_update(struct node_t *owner, subnet_t *subnet, bool up);
extern int maskcmp(const void *a, const void *b, size_t masklen);
extern void maskcpy(void *dest, const void *src, size_t masklen, size_t len);
extern void mask(void *mask, size_t masklen, size_t len);
extern bool subnetcheck(const subnet_t subnet);
extern bool maskcheck(const void *mask, size_t masklen, size_t len);
extern bool net2str(char *netstr, size_t len, const subnet_t *subnet);
extern bool str2net(subnet_t *subnet, const char *netstr);
extern subnet_t *lookup_subnet(struct node_t *owner, const subnet_t *subnet);
extern subnet_t *lookup_subnet_mac(const struct node_t *owner, const mac_t *address);
extern subnet_t *lookup_subnet_ipv4(const ipv4_t *address);
extern subnet_t *lookup_subnet_ipv6(const ipv6_t *address);
extern bool dump_subnets(struct connection_t *c);
extern void subnet_cache_flush_tables(void);
extern void subnet_cache_flush_table(subnet_type_t ipver);

#endif
