/*
    edge.h -- header for edge.c
    Copyright (C) 2001-2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2001-2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: edge.h,v 1.1.2.7 2002/03/22 11:43:46 guus Exp $
*/

#ifndef __TINC_EDGE_H__
#define __TINC_EDGE_H__

#include <avl_tree.h>

#include "net.h"
#include "node.h"
#include "connection.h"

typedef struct halfconnection_t {
  struct node_t *node;             /* node associated with this end of the connection */
//  sockaddr_t tcpaddress;           /* real (internet) ip on this end of the meta connection */
  sockaddr_t udpaddress;           /* real (internet) ip on this end of the vpn connection */
} halfconnection_t;

typedef struct edge_t {
  struct halfconnection_t from;
  struct halfconnection_t to;

  long int options;                /* options turned on for this edge */
  int weight;                      /* weight of this edge */
  
  struct connection_t *connection; /* connection associated with this edge, if available */
} edge_t;

extern avl_tree_t *edge_tree;    /* Tree with all known edges (replaces active_tree) */
extern avl_tree_t *edge_weight_tree; /* Tree with all known edges sorted on weight */

extern void init_edges(void);
extern void exit_edges(void);
extern edge_t *new_edge(void);
extern void free_edge(edge_t *);
extern avl_tree_t *new_edge_tree(void);
extern void free_edge_tree(avl_tree_t *);
extern void edge_add(edge_t *);
extern void edge_del(edge_t *);
extern edge_t *lookup_edge(struct node_t *, struct node_t *);
extern void dump_edges(void);

#endif /* __TINC_EDGE_H__ */
