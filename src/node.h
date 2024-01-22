#ifndef TINC_NODE_H
#define TINC_NODE_H

/*
    node.h -- header for node.c
    Copyright (C) 2001-2013 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "splay_tree.h"
#include "cipher.h"
#include "connection.h"
#include "digest.h"
#include "event.h"
#include "subnet.h"
#include "compression.h"

typedef union node_status_t {
	struct {
		bool unused_active: 1;          /* 1 if active (not used for nodes) */
		bool validkey: 1;               /* 1 if we currently have a valid key for him */
		bool waitingforkey: 1;          /* 1 if we already sent out a request */
		bool visited: 1;                /* 1 if this node has been visited by one of the graph algorithms */
		bool reachable: 1;              /* 1 if this node is reachable in the graph */
		bool indirect: 1;               /* 1 if this node is not directly reachable by us */
		bool sptps: 1;                  /* 1 if this node supports SPTPS */
		bool udp_confirmed: 1;          /* 1 if the address is one that we received UDP traffic on */
		bool send_locally: 1;           /* 1 if the next UDP packet should be sent on the local network */
		bool udppacket: 1;              /* 1 if the most recently received packet was UDP */
		bool validkey_in: 1;            /* 1 if we have sent a valid key to him */
		bool has_address: 1;            /* 1 if we know an external address for this node */
		bool ping_sent: 1;              /* 1 if we sent a UDP probe but haven't received the reply yet */
	};
	uint32_t value;
} node_status_t;

typedef struct node_t {
	char *name;                             /* name of this node */
	char *hostname;                         /* the hostname of its real ip */
	node_id_t id;                           /* unique node ID (name hash) */
	uint32_t options;                       /* options turned on for this node */

	size_t sock;                            /* Socket to use for outgoing UDP packets */
	sockaddr_t address;                     /* his real (internet) ip to send UDP packets to */

	node_status_t status;
	time_t last_state_change;
	time_t last_req_key;

	ecdsa_t *ecdsa;                         /* His public ECDSA key */
	sptps_t sptps;

#ifndef DISABLE_LEGACY
	cipher_t *incipher;                     /* Cipher for UDP packets */
	digest_t *indigest;                     /* Digest for UDP packets */

	cipher_t *outcipher;                    /* Cipher for UDP packets */
	digest_t *outdigest;                    /* Digest for UDP packets */
#endif

	compression_level_t incompression;      /* Compression level, 0 = no compression */
	compression_level_t outcompression;     /* Compression level, 0 = no compression */

	int distance;
	int weighted_distance;
	struct node_t *nexthop;                 /* nearest node from us to him */
	struct edge_t *prevedge;                /* nearest node from him to us */
	struct node_t *via;                     /* next hop for UDP packets */

	splay_tree_t subnet_tree;               /* Pointer to a tree of subnets belonging to this node */

	splay_tree_t edge_tree;                 /* Edges with this node as one of the endpoints */

	struct connection_t *connection;        /* Connection associated with this node (if a direct connection exists) */

	uint32_t sent_seqno;                    /* Sequence number last sent to this node */
	uint32_t received_seqno;                /* Sequence number last received from this node */
	uint32_t received;                      /* Total valid packets received from this node */
	uint32_t farfuture;                     /* Packets in a row that have arrived from the far future */
	uint8_t *late;                          /* Bitfield marking late packets */

	struct timeval udp_reply_sent;          /* Last time a (gratuitous) UDP probe reply was sent */
	struct timeval udp_ping_sent;           /* Last time a UDP probe was sent */
	int udp_ping_rtt;                       /* Round trip time of UDP ping (in microseconds; or -1 if !status.udp_confirmed) */
	timeout_t udp_ping_timeout;             /* Ping timeout event */

	struct timeval mtu_ping_sent;           /* Last time a MTU probe was sent */

	struct timeval mtu_info_sent;           /* Last time a MTU_INFO message was sent */
	struct timeval udp_info_sent;           /* Last time a UDP_INFO message was sent */

	length_t maxrecentlen;                  /* Maximum size of recently received packets */

	length_t mtu;                           /* Maximum size of packets to send to this node */
	length_t minmtu;                        /* Probed minimum MTU */
	length_t maxmtu;                        /* Probed maximum MTU */
	int mtuprobes;                          /* Number of probes */

	uint64_t in_packets;
	uint64_t in_bytes;
	uint64_t out_packets;
	uint64_t out_bytes;

	struct address_cache_t *address_cache;
} node_t;

extern struct node_t *myself;
extern splay_tree_t node_tree;

extern void exit_nodes(void);
extern void free_node(node_t *n);
extern node_t *new_node(const char *name) ATTR_MALLOC ATTR_DEALLOCATOR(free_node);
extern void node_add(node_t *n);
extern void node_del(node_t *n);
extern node_t *lookup_node(char *name);
extern node_t *lookup_node_id(const node_id_t *id);
extern node_t *lookup_node_udp(const sockaddr_t *sa);
extern bool dump_nodes(struct connection_t *c);
extern bool dump_traffic(struct connection_t *c);
extern void update_node_udp(node_t *n, const sockaddr_t *sa);

#endif
