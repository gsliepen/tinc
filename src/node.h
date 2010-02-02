/*
    node.h -- header for node.c
    Copyright (C) 2001-2010 Guus Sliepen <guus@tinc-vpn.org>,
                  2001-2005 Ivo Timmermans

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

#ifndef __TINC_NODE_H__
#define __TINC_NODE_H__

#include "avl_tree.h"
#include "connection.h"
#include "event.h"
#include "list.h"
#include "subnet.h"

typedef struct node_status_t {
	int unused_active:1;			/* 1 if active (not used for nodes) */
	int validkey:1;				/* 1 if we currently have a valid key for him */
	int unused_waitingforkey:1;		/* 1 if we already sent out a request */
	int visited:1;				/* 1 if this node has been visited by one of the graph algorithms */
	int reachable:1;			/* 1 if this node is reachable in the graph */
	int indirect:1;				/* 1 if this node is not directly reachable by us */
	int unused:26;
} node_status_t;

typedef struct node_t {
	char *name;				/* name of this node */
	uint32_t options;			/* options turned on for this node */

	sockaddr_t address;			/* his real (internet) ip to send UDP packets to */
	char *hostname;				/* the hostname of its real ip */

	node_status_t status;
	time_t last_req_key;

	const EVP_CIPHER *incipher;		/* Cipher type for UDP packets received from him */
	char *inkey;				/* Cipher key and iv */
	int inkeylength;			/* Cipher key and iv length */
	EVP_CIPHER_CTX inctx;			/* Cipher context */
	
	const EVP_CIPHER *outcipher;		/* Cipher type for UDP packets sent to him*/
	char *outkey;				/* Cipher key and iv */
	int outkeylength;			/* Cipher key and iv length */
	EVP_CIPHER_CTX outctx;			/* Cipher context */
	
	const EVP_MD *indigest;			/* Digest type for MAC of packets received from him */
	int inmaclength;			/* Length of MAC */

	const EVP_MD *outdigest;		/* Digest type for MAC of packets sent to him*/
	int outmaclength;			/* Length of MAC */

	int incompression;			/* Compressionlevel, 0 = no compression */
	int outcompression;			/* Compressionlevel, 0 = no compression */

	struct node_t *nexthop;			/* nearest node from us to him */
	struct node_t *via;			/* next hop for UDP packets */

	avl_tree_t *subnet_tree;		/* Pointer to a tree of subnets belonging to this node */

	avl_tree_t *edge_tree;			/* Edges with this node as one of the endpoints */

	struct connection_t *connection;	/* Connection associated with this node (if a direct connection exists) */

	uint32_t sent_seqno;			/* Sequence number last sent to this node */
	uint32_t received_seqno;		/* Sequence number last received from this node */
	unsigned char late[16];			/* Bitfield marking late packets */

	length_t mtu;				/* Maximum size of packets to send to this node */
	length_t minmtu;			/* Probed minimum MTU */
	length_t maxmtu;			/* Probed maximum MTU */
	int mtuprobes;				/* Number of probes */
	event_t *mtuevent;			/* Probe event */
} node_t;

extern struct node_t *myself;
extern avl_tree_t *node_tree;
extern avl_tree_t *node_udp_tree;

extern void init_nodes(void);
extern void exit_nodes(void);
extern node_t *new_node(void) __attribute__ ((__malloc__));
extern void free_node(node_t *);
extern void node_add(node_t *);
extern void node_del(node_t *);
extern node_t *lookup_node(char *);
extern node_t *lookup_node_udp(const sockaddr_t *);
extern void update_node_udp(node_t *, const sockaddr_t *);
extern void dump_nodes(void);

#endif							/* __TINC_NODE_H__ */
