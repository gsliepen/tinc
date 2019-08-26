#ifndef TINC_CONNECTION_H
#define TINC_CONNECTION_H

/*
    connection.h -- header for connection.c
    Copyright (C) 2000-2016 Guus Sliepen <guus@tinc-vpn.org>,
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

#include <openssl/rsa.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_CIPHER_CTX_reset(c) EVP_CIPHER_CTX_cleanup(c)
#endif

#include "avl_tree.h"

#define OPTION_INDIRECT         0x0001
#define OPTION_TCPONLY          0x0002
#define OPTION_PMTU_DISCOVERY   0x0004
#define OPTION_CLAMP_MSS        0x0008

typedef struct connection_status_t {
	unsigned int pinged: 1;         /* sent ping */
	unsigned int active: 1;         /* 1 if active.. */
	unsigned int connecting: 1;     /* 1 if we are waiting for a non-blocking connect() to finish */
	unsigned int unused_termreq: 1; /* the termination of this connection was requested */
	unsigned int remove: 1;         /* Set to 1 if you want this connection removed */
	unsigned int timeout: 1;        /* 1 if gotten timeout */
	unsigned int encryptout: 1;     /* 1 if we can encrypt outgoing traffic */
	unsigned int decryptin: 1;      /* 1 if we have to decrypt incoming traffic */
	unsigned int mst: 1;            /* 1 if this connection is part of a minimum spanning tree */
	unsigned int proxy_passed: 1;   /* 1 if we are connecting via a proxy and we have finished talking with it */
	unsigned int tarpit: 1;         /* 1 if the connection should be added to the tarpit */
	unsigned int unused: 21;
} connection_status_t;

#include "edge.h"
#include "net.h"
#include "node.h"

typedef struct connection_t {
	char *name;                     /* name he claims to have */

	union sockaddr_t address;       /* his real (internet) ip */
	char *hostname;                 /* the hostname of its real ip */
	int protocol_version;           /* used protocol */

	int socket;                     /* socket used for this connection */
	uint32_t options;               /* options for this connection */
	connection_status_t status;     /* status info */
	int estimated_weight;           /* estimation for the weight of the edge for this connection */
	struct timeval start;           /* time this connection was started, used for above estimation */
	struct outgoing_t *outgoing;    /* used to keep track of outgoing connections */

	struct node_t *node;            /* node associated with the other end */
	struct edge_t *edge;            /* edge associated with this connection */

	RSA *rsa_key;                   /* his public/private key */
	const EVP_CIPHER *incipher;     /* Cipher he will use to send data to us */
	const EVP_CIPHER *outcipher;    /* Cipher we will use to send data to him */
	EVP_CIPHER_CTX *inctx;          /* Context of encrypted meta data that will come from him to us */
	EVP_CIPHER_CTX *outctx;         /* Context of encrypted meta data that will be sent from us to him */
	uint64_t inbudget;              /* Encrypted bytes send budget */
	uint64_t outbudget;             /* Encrypted bytes receive budget */
	char *inkey;                    /* His symmetric meta key + iv */
	char *outkey;                   /* Our symmetric meta key + iv */
	int inkeylength;                /* Length of his key + iv */
	int outkeylength;               /* Length of our key + iv */
	const EVP_MD *indigest;
	const EVP_MD *outdigest;
	int inmaclength;
	int outmaclength;
	int incompression;
	int outcompression;
	char *mychallenge;              /* challenge we received from him */
	char *hischallenge;             /* challenge we sent to him */

	char buffer[MAXBUFSIZE];        /* metadata input buffer */
	int buflen;                     /* bytes read into buffer */
	int reqlen;                     /* length of incoming request */
	length_t tcplen;                /* length of incoming TCPpacket */
	int allow_request;              /* defined if there's only one request possible */

	char *outbuf;                   /* metadata output buffer */
	int outbufstart;                /* index of first meaningful byte in output buffer */
	int outbuflen;                  /* number of meaningful bytes in output buffer */
	int outbufsize;                 /* number of bytes allocated to output buffer */

	time_t last_ping_time;          /* last time we saw some activity from the other end or pinged them */
	time_t last_flushed_time;       /* last time buffer was empty. Only meaningful if outbuflen > 0 */

	avl_tree_t *config_tree;        /* Pointer to configuration tree belonging to him */
} connection_t;

extern avl_tree_t *connection_tree;
extern connection_t *everyone;

extern void init_connections(void);
extern void exit_connections(void);
extern connection_t *new_connection(void) __attribute__((__malloc__));
extern void free_connection(connection_t *c);
extern void free_connection_partially(connection_t *c);
extern void connection_add(connection_t *c);
extern void connection_del(connection_t *c);
extern void dump_connections(void);

#endif
