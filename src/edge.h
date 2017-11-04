#ifndef TINC_EDGE_H
#define TINC_EDGE_H

/*
    edge.h -- header for edge.c
    Copyright (C) 2001-2006 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "avl_tree.h"
#include "connection.h"
#include "net.h"
#include "node.h"

typedef struct edge_t {
	struct node_t *from;
	struct node_t *to;
	sockaddr_t address;

	uint32_t options;                /* options turned on for this edge */
	int weight;                      /* weight of this edge */

	struct connection_t *connection; /* connection associated with this edge, if available */
	struct edge_t *reverse;          /* edge in the opposite direction, if available */
} edge_t;

extern avl_tree_t *edge_weight_tree;     /* Tree with all known edges sorted on weight */

extern void init_edges(void);
extern void exit_edges(void);
extern edge_t *new_edge(void) __attribute__((__malloc__));
extern void free_edge(edge_t *e);
extern avl_tree_t *new_edge_tree(void) __attribute__((__malloc__));
extern void free_edge_tree(avl_tree_t *edge_tree);
extern void edge_add(edge_t *e);
extern void edge_del(edge_t *e);
extern edge_t *lookup_edge(struct node_t *from, struct node_t *to);
extern void dump_edges(void);

#endif
