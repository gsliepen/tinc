/*
    connlist.h -- header for connlist.c
    Copyright (C) 2000 Guus Sliepen <guus@sliepen.warande.net>,
                  2000 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: connlist.h,v 1.1.2.3 2000/10/14 17:04:13 guus Exp $
*/

#ifndef __TINC_CONNLIST_H__
#define __TINC_CONNLIST_H__

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "net.h"
#include "conf.h"

typedef struct conn_list_t {
  char *name;                      /* name of this connection */
  ipv4_t address;                    /* his real (internet) ip */
  char *hostname;                  /* the hostname of its real ip */
  short unsigned int port;         /* his portnumber */
  int protocol_version;            /* used protocol */
  int options;                     /* options turned on for this connection */

  int flags;                       /* his flags */
  int socket;                      /* our udp vpn socket */
  int meta_socket;                 /* our tcp meta socket */
  status_bits_t status;            /* status info */
  packet_queue_t *sq;              /* pending outgoing packets */
  packet_queue_t *rq;              /* pending incoming packets (they have no
				      valid key to be decrypted with) */
  RSA *public_key;                 /* the other party's public key */

  EVP_CIPHER_CTX *cipher_inctx;    /* Context of encrypted meta data that will come from him to us */
  EVP_CIPHER_CTX *cipher_outctx;   /* Context of encrypted meta data that will be sent from us to him */

  EVP_CIPHER_CTX *cipher_pktctx;   /* Context of encrypted vpn packets that will be sent to him */
  EVP_CIPHER *cipher_pkttype;      /* Cipher type for encrypted vpn packets */ 
  char *cipher_pktkey;             /* Cipher key */

  char *buffer;                    /* metadata input buffer */
  int buflen;                      /* bytes read into buffer */
  int reqlen;                      /* length of first request in buffer */
  int allow_request;               /* defined if there's only one request possible */

  time_t last_ping_time;           /* last time we saw some activity from the other end */  
  int want_ping;                   /* 0 if there's no need to check for activity. Shouldn't this go into status? (GS) */

  char *mychallenge;               /* challenge we received from him */
  char *hischallenge;              /* challenge we sent to him */

  struct conn_list_t *nexthop;     /* nearest meta-hop in this direction, will be changed to myuplink (GS) */
  struct conn_list_t *hisuplink;   /* his nearest meta-hop in our direction */
  struct conn_list_t *myuplink;    /* our nearest meta-hop in his direction */

  struct subnet_t *subnets;        /* Pointer to a list of subnets belonging to this connection */

  struct config_t *config;         /* Pointer to configuration tree belonging to this host */

  struct conn_list_t *next;        /* after all, it's a list of connections */
  struct conn_list_t *prev;        /* doubly linked for O(1) deletions */
} conn_list_t;

#include "subnet.h"

extern conn_list_t *conn_list;
extern conn_list_t *myself;

extern conn_list_t *new_conn_list();
extern void free_conn_list(conn_list_t *);
extern void add_conn_list(conn_list_t *);
extern void del_conn_list(conn_list_t *);
extern conn_list_t *lookup_id(char *);
extern conn_list_t *lookup_conn_list_mac(mac_t);
extern conn_list_t *lookup_conn_list_ipv4(ipv4_t);
extern conn_list_t *lookup_conn_list_ipv6(ipv6_t);
extern void dump_conn_list(void);
extern int read_host_config(conn_list_t *);

#endif /* __TINC_CONNLIST_H__ */
