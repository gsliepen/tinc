/*
    node.h -- header for node.c
    Copyright (C) 2001-2006 Guus Sliepen <guus@tinc-vpn.org>,
                  2001-2005 Ivo Timmermans

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#ifndef __TINC_NODE_H__
#define __TINC_NODE_H__

#include "avl_tree.h"
#include "connection.h"
#include "event.h"
#include "list.h"
#include "subnet.h"

typedef struct node_status_t {
	int active:1;				/* 1 if active.. */
	int validkey:1;				/* 1 if we currently have a valid key for him */
	int waitingforkey:1;			/* 1 if we already sent out a request */
	int visited:1;				/* 1 if this node has been visited by one of the graph algorithms */
	int reachable:1;			/* 1 if this node is reachable in the graph */
	int indirect:1;				/* 1 if this node is not directly reachable by us */
	int unused:26;
} node_status_t;

typedef struct node_t {
	char *name;				/* name of this node */
	long int options;			/* options turned on for this node */

	sockaddr_t address;			/* his real (internet) ip to send UDP packets to */
	char *hostname;				/* the hostname of its real ip */

	node_status_t status;

	const EVP_CIPHER *cipher;		/* Cipher type for UDP packets */
	char *key;				/* Cipher key and iv */
	int keylength;				/* Cipher key and iv length */
	EVP_CIPHER_CTX packet_ctx;		/* Cipher context */
	
	const EVP_MD *digest;			/* Digest type for MAC */
	int maclength;				/* Length of MAC */

	int compression;			/* Compressionlevel, 0 = no compression */

	list_t *queue;				/* Queue for packets awaiting to be encrypted */

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
extern void dump_nodes(void);

#endif							/* __TINC_NODE_H__ */
