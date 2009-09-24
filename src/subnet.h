/*
    subnet.h -- header for subnet.c
    Copyright (C) 2000-2009 Guus Sliepen <guus@tinc-vpn.org>,
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

#ifndef __TINC_SUBNET_H__
#define __TINC_SUBNET_H__

#include "net.h"

typedef enum subnet_type_t {
	SUBNET_MAC = 0,
	SUBNET_IPV4,
	SUBNET_IPV6,
	SUBNET_TYPES				/* Guardian */
} subnet_type_t;

typedef struct subnet_mac_t {
	mac_t address;
} subnet_mac_t;

typedef struct subnet_ipv4_t {
	ipv4_t address;
	int prefixlength;
} subnet_ipv4_t;

typedef struct subnet_ipv6_t {
	ipv6_t address;
	int prefixlength;
} subnet_ipv6_t;

#include "node.h"

typedef struct subnet_t {
	struct node_t *owner;		/* the owner of this subnet */

	subnet_type_t type;		/* subnet type (IPv4? IPv6? MAC? something even weirder?) */
	time_t expires;			/* expiry time */
	int weight;			/* weight (higher value is higher priority) */

	/* And now for the actual subnet: */

	union net {
		subnet_mac_t mac;
		subnet_ipv4_t ipv4;
		subnet_ipv6_t ipv6;
	} net;
} subnet_t;

#define MAXNETSTR 64

extern int subnet_compare(const struct subnet_t *, const struct subnet_t *);
extern subnet_t *new_subnet(void) __attribute__ ((__malloc__));
extern void free_subnet(subnet_t *);
extern void init_subnets(void);
extern void exit_subnets(void);
extern avl_tree_t *new_subnet_tree(void) __attribute__ ((__malloc__));
extern void free_subnet_tree(avl_tree_t *);
extern void subnet_add(struct node_t *, subnet_t *);
extern void subnet_del(struct node_t *, subnet_t *);
extern void subnet_update(struct node_t *, subnet_t *, bool);
extern bool net2str(char *, int, const subnet_t *);
extern bool str2net(subnet_t *, const char *);
extern subnet_t *lookup_subnet(const struct node_t *, const subnet_t *);
extern subnet_t *lookup_subnet_mac(const mac_t *);
extern subnet_t *lookup_subnet_ipv4(const ipv4_t *);
extern subnet_t *lookup_subnet_ipv6(const ipv6_t *);
extern void dump_subnets(void);
extern void subnet_cache_flush(void);

#endif							/* __TINC_SUBNET_H__ */
