/*
    node.h -- header for node.c
    Copyright (C) 2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: node.h,v 1.1.2.3 2001/10/10 08:49:47 guus Exp $
*/

#ifndef __TINC_NODE_H__
#define __TINC_NODE_H__

#include <avl_tree.h>

typedef struct node_t {
  char *name;                      /* name of this connection */
  int protocol_version;            /* used protocol */
  long int options;                /* options turned on for this connection */

  ipv4_t address;                  /* his real (internet) ip to send UDP packets to */
  short unsigned int port;         /* port number of UDP connection */
  char *hostname;                  /* the hostname of its real ip */

  status_bits_t status;            /* status info */

  EVP_CIPHER *cipher;              /* Cipher type for UDP packets */ 
  char *key;                       /* Cipher key and iv */
  int keylength;                   /* Cipher key and iv length*/

  list_t *queue;                   /* Queue for packets awaiting to be encrypted */

  struct node_t *nexthop;          /* nearest meta-hop from us to him */
  struct node_t *prevhop;          /* nearest meta-hop from him to us */
  struct node_t *via;              /* next hop for UDP packets */
  
  avl_tree_t *subnet_tree;         /* Pointer to a tree of subnets belonging to this node */

  struct config_t *config;         /* Pointer to configuration tree belonging to this node */
} node_t;

struct node_t *myself;
extern avl_tree_t *node_tree;

#endif /* __TINC_NODE_H__ */
