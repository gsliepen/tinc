/*
    connection.h -- header for connection.c
    Copyright (C) 2000,2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2000,2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: connection.h,v 1.1.2.15 2001/10/10 09:42:29 guus Exp $
*/

#ifndef __TINC_CONNECTION_H__
#define __TINC_CONNECTION_H__

#include <avl_tree.h>
#include <list.h>

#include "config.h"

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
#include "vertex.h"

typedef struct status_bits_t {
  int pinged:1;                    /* sent ping */
  int meta:1;                      /* meta connection exists */
  int active:1;                    /* 1 if active.. */
  int outgoing:1;                  /* I myself asked for this conn */
  int termreq:1;                   /* the termination of this connection was requested */
  int remove:1;                    /* Set to 1 if you want this connection removed */
  int timeout:1;                   /* 1 if gotten timeout */
  int validkey:1;                  /* 1 if we currently have a valid key for him */
  int waitingforkey:1;             /* 1 if we already sent out a request */
  int dataopen:1;                  /* 1 if we have a valid UDP connection open */
  int encryptout:1;		   /* 1 if we can encrypt outgoing traffic */
  int decryptin:1;                 /* 1 if we have to decrypt incoming traffic */
  int unused:18;
} status_bits_t;

#define OPTION_INDIRECT		0x0001
#define OPTION_TCPONLY		0x0002

typedef struct connection_t {
  ipv4_t address;                  /* his real (internet) ip */
  short unsigned int port;         /* port number of meta connection */
  char *hostname;                  /* the hostname of its real ip */
  int protocol_version;            /* used protocol */

  int socket;                      /* socket used for this connection */
  status_bits_t status;            /* status info */

  struct node_t *node;             /* node associated with the other end */
  struct vertex_t *vertex;         /* vertex associated with this connection */

  RSA *rsa_key;                    /* his public/private key */
  EVP_CIPHER *incipher;            /* Cipher he will use to send data to us */
  EVP_CIPHER *outcipher;           /* Cipher we will use to send data to him */
  EVP_CIPHER_CTX *inctx;           /* Context of encrypted meta data that will come from him to us */
  EVP_CIPHER_CTX *outctx;          /* Context of encrypted meta data that will be sent from us to him */
  char *inkey;                     /* His symmetric meta key + iv */
  char *outkey;                    /* Our symmetric meta key + iv */
  int inkeylength;                 /* Length of his key + iv */
  int outkeylength;                /* Length of our key + iv */
  char *mychallenge;               /* challenge we received from him */
  char *hischallenge;              /* challenge we sent to him */

  char buffer[MAXBUFSIZE];         /* metadata input buffer */
  int buflen;                      /* bytes read into buffer */
  int tcplen;                      /* length of incoming TCPpacket */
  int allow_request;               /* defined if there's only one request possible */

  time_t last_ping_time;           /* last time we saw some activity from the other end */
} connection_t;

extern avl_tree_t *connection_tree;

#endif /* __TINC_CONNECTION_H__ */
