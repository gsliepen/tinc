/*
    node.h -- header for node.c
    Copyright (C) 2001-2012 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "splay_tree.h"
#include "cipher.h"
#include "connection.h"
#include "digest.h"
#include "event.h"
#include "subnet.h"

typedef struct node_status_t {
	unsigned int unused_active:1;           /* 1 if active (not used for nodes) */
	unsigned int validkey:1;                /* 1 if we currently have a valid key for him */
	unsigned int waitingforkey:1;           /* 1 if we already sent out a request */
	unsigned int visited:1;                 /* 1 if this node has been visited by one of the graph algorithms */
	unsigned int reachable:1;               /* 1 if this node is reachable in the graph */
	unsigned int indirect:1;                /* 1 if this node is not directly reachable by us */
	unsigned int sptps:1;                   /* 1 if this node supports SPTPS */
	unsigned int udp_confirmed:1;           /* 1 if the address is one that we received UDP traffic on */
	unsigned int unused:24;
} node_status_t;

typedef struct node_t {
	char *name;                             /* name of this node */
	uint32_t options;                       /* options turned on for this node */

	int sock;                               /* Socket to use for outgoing UDP packets */
	sockaddr_t address;                     /* his real (internet) ip to send UDP packets to */
	char *hostname;                         /* the hostname of its real ip */

	struct node_t *disjoint_set;            /* Pointer to the parent node in the disjoint set (used in Kruskal's algorithm) */

	node_status_t status;
	time_t last_state_change;
	time_t last_req_key;

	ecdsa_t ecdsa;                          /* His public ECDSA key */
	sptps_t sptps;

	cipher_t incipher;                      /* Cipher for UDP packets */
	digest_t indigest;                      /* Digest for UDP packets */

	cipher_t outcipher;                     /* Cipher for UDP packets */
	digest_t outdigest;                     /* Digest for UDP packets */

	int incompression;                      /* Compressionlevel, 0 = no compression */
	int outcompression;                     /* Compressionlevel, 0 = no compression */

	int distance;
	struct node_t *nexthop;                 /* nearest node from us to him */
	struct edge_t *prevedge;                /* nearest node from him to us */
	struct node_t *via;                     /* next hop for UDP packets */

	splay_tree_t *subnet_tree;              /* Pointer to a tree of subnets belonging to this node */

	splay_tree_t *edge_tree;                /* Edges with this node as one of the endpoints */

	struct connection_t *connection;        /* Connection associated with this node (if a direct connection exists) */

	uint32_t sent_seqno;                    /* Sequence number last sent to this node */
	uint32_t received_seqno;                /* Sequence number last received from this node */
	uint32_t received;                      /* Total valid packets received from this node */
	uint32_t prev_received_seqno;
	uint32_t prev_received;
	uint32_t farfuture;                     /* Packets in a row that have arrived from the far future */
	unsigned char* late;                    /* Bitfield marking late packets */

	length_t mtu;                           /* Maximum size of packets to send to this node */
	length_t minmtu;                        /* Probed minimum MTU */
	length_t maxmtu;                        /* Probed maximum MTU */
	int mtuprobes;                          /* Number of probes */
	timeout_t mtutimeout;                   /* Probe event */
	struct timeval probe_time;              /* Time the last probe was sent or received */
	int probe_counter;                      /* Number of probes received since last burst was sent */
	float rtt;                              /* Last measured round trip time */
	float bandwidth;                        /* Last measured bandwidth */
	float packetloss;                       /* Last measured packet loss rate */

	uint64_t in_packets;
	uint64_t in_bytes;
	uint64_t out_packets;
	uint64_t out_bytes;
} node_t;

extern struct node_t *myself;
extern splay_tree_t *node_tree;

extern void init_nodes(void);
extern void exit_nodes(void);
extern node_t *new_node(void) __attribute__ ((__malloc__));
extern void free_node(node_t *);
extern void node_add(node_t *);
extern void node_del(node_t *);
extern node_t *lookup_node(char *);
extern node_t *lookup_node_udp(const sockaddr_t *);
extern bool dump_nodes(struct connection_t *);
extern bool dump_traffic(struct connection_t *);
extern void update_node_udp(node_t *, const sockaddr_t *);

#endif /* __TINC_NODE_H__ */
