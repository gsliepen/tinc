/*
    edge.h -- header for edge.c
    Copyright (C) 2001-2003 Guus Sliepen <guus@sliepen.eu.org>,
                  2001-2003 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: edge.h,v 1.1.2.14 2003/07/17 15:06:26 guus Exp $
*/

#ifndef __TINC_EDGE_H__
#define __TINC_EDGE_H__

#include "avl_tree.h"
#include "connection.h"
#include "net.h"
#include "node.h"

typedef struct edge_t {
	struct node_t *from;
	struct node_t *to;
	sockaddr_t address;

	long int options;			/* options turned on for this edge */
	int weight;					/* weight of this edge */

	struct connection_t *connection;	/* connection associated with this edge, if available */
	struct edge_t *reverse;		/* edge in the opposite direction, if available */
} edge_t;

extern avl_tree_t *edge_weight_tree;	/* Tree with all known edges sorted on weight */

extern void init_edges(void);
extern void exit_edges(void);
extern edge_t *new_edge(void) __attribute__ ((malloc));
extern void free_edge(edge_t *);
extern avl_tree_t *new_edge_tree(void) __attribute__ ((malloc));
extern void free_edge_tree(avl_tree_t *);
extern void edge_add(edge_t *);
extern void edge_del(edge_t *);
extern edge_t *lookup_edge(struct node_t *, struct node_t *);
extern void dump_edges(void);

#endif							/* __TINC_EDGE_H__ */
