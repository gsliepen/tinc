/*
    connection.h -- header for connection.c
    Copyright (C) 2000-2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2000-2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: connection.h,v 1.1.2.26 2002/02/20 19:25:09 guus Exp $
*/

#ifndef __TINC_CONNECTION_H__
#define __TINC_CONNECTION_H__

#include <sys/time.h>

#include <avl_tree.h>
#include <list.h>

#ifdef HAVE_OPENSSL_EVP_H
# include <openssl/evp.h>
#else
# include <evp.h>
#endif

#ifdef HAVE_OPENSSL_RSA_H
# include <openssl/rsa.h>
#else
# include <rsa.h>
#endif

#include "net.h"
#include "conf.h"

#include "node.h"
#include "edge.h"

#define OPTION_INDIRECT		0x0001
#define OPTION_TCPONLY		0x0002

typedef struct connection_status_t {
  int pinged:1;                    /* sent ping */
  int active:1;                    /* 1 if active.. */
  int connecting:1;                /* 1 if we are waiting for a non-blocking connect() to finish */
  int termreq:1;                   /* the termination of this connection was requested */
  int remove:1;                    /* Set to 1 if you want this connection removed */
  int timeout:1;                   /* 1 if gotten timeout */
  int encryptout:1;		   /* 1 if we can encrypt outgoing traffic */
  int decryptin:1;                 /* 1 if we have to decrypt incoming traffic */
  int mst:1;			   /* 1 if this connection is part of a minimum spanning tree */
  int unused:18;
} connection_status_t;

typedef struct connection_t {
  char *name;                      /* name he claims to have */

  sockaddr_t address;              /* his real (internet) ip */
  char *hostname;                  /* the hostname of its real ip */
  int protocol_version;            /* used protocol */

  int socket;                      /* socket used for this connection */
  long int options;                /* options for this connection */
  struct connection_status_t status; /* status info */
  int estimated_weight;            /* estimation for the weight of the edge for this connection */
  struct timeval start;            /* time this connection was started, used for above estimation */
  struct outgoing_t *outgoing;     /* used to keep track of outgoing connections */

  struct node_t *node;             /* node associated with the other end */
  struct edge_t *edge;             /* edge associated with this connection */

  RSA *rsa_key;                    /* his public/private key */
  const EVP_CIPHER *incipher;      /* Cipher he will use to send data to us */
  const EVP_CIPHER *outcipher;     /* Cipher we will use to send data to him */
  EVP_CIPHER_CTX *inctx;           /* Context of encrypted meta data that will come from him to us */
  EVP_CIPHER_CTX *outctx;          /* Context of encrypted meta data that will be sent from us to him */
  char *inkey;                     /* His symmetric meta key + iv */
  char *outkey;                    /* Our symmetric meta key + iv */
  int inkeylength;                 /* Length of his key + iv */
  int outkeylength;                /* Length of our key + iv */
  const EVP_MD *indigest;
  const EVP_MD *outdigest;
  int inmaclength;
  int outmaclength;
  int incompression;
  int outcompression;
  char *mychallenge;               /* challenge we received from him */
  char *hischallenge;              /* challenge we sent to him */

  char buffer[MAXBUFSIZE];         /* metadata input buffer */
  int buflen;                      /* bytes read into buffer */
  int tcplen;                      /* length of incoming TCPpacket */
  int allow_request;               /* defined if there's only one request possible */

  time_t last_ping_time;           /* last time we saw some activity from the other end */

  avl_tree_t *config_tree;         /* Pointer to configuration tree belonging to him */
} connection_t;

extern avl_tree_t *connection_tree;

extern void init_connections(void);
extern void exit_connections(void);
extern connection_t *new_connection(void);
extern void free_connection(connection_t *);
extern void connection_add(connection_t *);
extern void connection_del(connection_t *);
extern void dump_connections(void);
extern int read_connection_config(connection_t *);

#endif /* __TINC_CONNECTION_H__ */
