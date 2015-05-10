/*
    edge.h -- header for edge.c
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

#ifndef __TINC_EDGE_H__
#define __TINC_EDGE_H__

#include "splay_tree.h"
#include "connection.h"
#include "net.h"
#include "node.h"

typedef struct edge_t {
	struct node_t *from;
	struct node_t *to;
	sockaddr_t address;
	sockaddr_t local_address;

	uint32_t options;                       /* options turned on for this edge */
	int weight;                             /* weight of this edge */
	int avg_rtt;                            /* average RTT */

	struct connection_t *connection;        /* connection associated with this edge, if available */
	struct edge_t *reverse;                 /* edge in the opposite direction, if available */
} edge_t;

extern splay_tree_t *edge_weight_tree;          /* Tree with all known edges sorted on weight */

extern void init_edges(void);
extern void exit_edges(void);
extern edge_t *new_edge(void) __attribute__ ((__malloc__));
extern void free_edge(edge_t *);
extern splay_tree_t *new_edge_tree(void) __attribute__ ((__malloc__));
extern void free_edge_tree(splay_tree_t *);
extern void edge_add(edge_t *);
extern void edge_del(edge_t *);
extern edge_t *lookup_edge(struct node_t *, struct node_t *);
extern edge_t *clone_edge(edge_t *);
extern bool dump_edges(struct connection_t *);

#endif /* __TINC_EDGE_H__ */
