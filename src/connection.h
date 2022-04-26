#ifndef TINC_CONNECTION_H
#define TINC_CONNECTION_H

/*
    connection.h -- header for connection.c
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

#include "buffer.h"
#include "cipher.h"
#include "digest.h"
#include "rsa.h"
#include "list.h"
#include "sptps.h"
#include "logger.h"

#define OPTION_INDIRECT         0x0001
#define OPTION_TCPONLY          0x0002
#define OPTION_PMTU_DISCOVERY   0x0004
#define OPTION_CLAMP_MSS        0x0008
#define OPTION_VERSION(x) ((x) >> 24) /* Top 8 bits are for protocol minor version */

typedef union connection_status_t {
	struct {
		bool pinged: 1;                 /* sent ping */
		bool unused_active: 1;
		bool connecting: 1;             /* 1 if we are waiting for a non-blocking connect() to finish */
		bool unused_termreq: 1;         /* the termination of this connection was requested */
		bool remove_unused: 1;          /* Set to 1 if you want this connection removed */
		bool timeout_unused: 1;         /* 1 if gotten timeout */
		bool encryptout: 1;             /* 1 if we can encrypt outgoing traffic */
		bool decryptin: 1;              /* 1 if we have to decrypt incoming traffic */
		bool mst: 1;                    /* 1 if this connection is part of a minimum spanning tree */
		bool control: 1;                /* 1 if this is a control connection */
		bool pcap: 1;                   /* 1 if this is a control connection requesting packet capture */
		bool log: 1;                    /* 1 if this is a control connection requesting log dump */
		bool log_color: 1;              /* 1 if this connection supports ANSI escape codes */
		bool invitation: 1;             /* 1 if this is an invitation */
		bool invitation_used: 1;        /* 1 if the invitation has been consumed */
		bool tarpit: 1;                 /* 1 if the connection should be added to the tarpit */
	};
	uint32_t value;
} connection_status_t;

#include "ecdsa.h"
#include "edge.h"
#include "net.h"
#include "node.h"

#ifndef DISABLE_LEGACY
typedef struct legacy_crypto_t {
	cipher_t cipher;
	digest_t digest;
	uint64_t budget;
} legacy_crypto_t;

bool init_crypto_by_nid(legacy_crypto_t *c, nid_t cipher, nid_t digest) ATTR_WARN_UNUSED;
bool init_crypto_by_name(legacy_crypto_t *c, const char *cipher, const char *digest) ATTR_WARN_UNUSED;
bool decrease_budget(legacy_crypto_t *c, size_t bytes) ATTR_WARN_UNUSED;

typedef struct legacy_ctx_t {
	rsa_t *rsa;                    /* his public RSA key or my private RSA key */
	legacy_crypto_t in;            /* cipher/digest he will use to send data to us */
	legacy_crypto_t out;           /* cipher/digest we will use to send data to him */
} legacy_ctx_t;

legacy_ctx_t *new_legacy_ctx(rsa_t *rsa);
void free_legacy_ctx(legacy_ctx_t *ctx);
#endif

typedef struct connection_t {
	char *name;                     /* name he claims to have */
	char *hostname;                 /* the hostname of its real ip */

	union sockaddr_t address;       /* his real (internet) ip */
	int protocol_major;             /* used protocol */
	int protocol_minor;             /* used protocol */

	int socket;                     /* socket used for this connection */
	uint32_t options;               /* options for this connection */
	connection_status_t status;     /* status info */
	int estimated_weight;           /* estimation for the weight of the edge for this connection */
	struct timeval start;           /* time this connection was started, used for above estimation */
	struct outgoing_t *outgoing;    /* used to keep track of outgoing connections */

	struct node_t *node;            /* node associated with the other end */
	struct edge_t *edge;            /* edge associated with this connection */

#ifndef DISABLE_LEGACY
	legacy_ctx_t *legacy;
#endif

	ecdsa_t *ecdsa;                 /* his public ECDSA key */
	sptps_t sptps;

	int outmaclength;
	debug_t log_level;              /* used for REQ_LOG */

	uint8_t *hischallenge;          /* The challenge we sent to him */
	uint8_t *mychallenge;           /* The challenge we received */

	struct buffer_t inbuf;
	struct buffer_t outbuf;
	io_t io;                        /* input/output event on this metadata connection */
	uint32_t tcplen;                /* length of incoming TCPpacket */
	uint32_t sptpslen;              /* length of incoming SPTPS packet */
	int allow_request;              /* defined if there's only one request possible */

	time_t last_ping_time;          /* last time we saw some activity from the other end or pinged them */

	splay_tree_t *config_tree;      /* Pointer to configuration tree belonging to him */
} connection_t;

extern list_t connection_list;
extern connection_t *everyone;

extern void init_connections(void);
extern void exit_connections(void);
extern void free_connection(connection_t *c);
extern connection_t *new_connection(void) ATTR_MALLOC ATTR_DEALLOCATOR(free_connection);
extern void connection_add(connection_t *c);
extern void connection_del(connection_t *c);
extern bool dump_connections(struct connection_t *c);

#endif
