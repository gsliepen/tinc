/*
    edge.h -- header for edge.c
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

    $Id: edge.h,v 1.1.2.1 2001/10/28 08:41:19 guus Exp $
*/

#ifndef __TINC_EDGE_H__
#define __TINC_EDGE_H__

#include <avl_tree.h>

#include "node.h"
#include "connection.h"

/* I don't know if halfconnection_t is useful... */

typedef struct halfconnection_t {
  struct node_t *node;             /* node associated with this end of the connection */

  ipv4_t address;                  /* real (internet) ip on this end of the meta connection */
  short unsigned int port;         /* port number of this end of the meta connection */
  char *hostname;                  /* the hostname of real ip */
} halfconnection_t;

typedef struct edge_t {
  struct node_t *from;
  struct node_t *to;

  long int options;                /* options turned on for this connection */
  int metric;                      /* weight of this edge */
  
  struct connection_t *connection; /* connection associated with this edge, if available */
} edge_t;

extern avl_tree_t *edge_tree;    /* Tree with all known vertices (replaces active_tree) */

extern void init_vertices(void);
extern void exit_vertices(void);
extern edge_t *new_edge(void);
extern void free_edge(edge_t *);
extern void edge_add(edge_t *);
extern void edge_del(edge_t *);
extern edge_t *lookup_edge(struct node_t *, struct node_t *);
extern void dump_vertices(void);

#endif /* __TINC_EDGE_H__ */
