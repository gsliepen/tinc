/*
    edge.c -- edge tree management
    Copyright (C) 2000-2006 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "system.h"

#include "avl_tree.h"
#include "edge.h"
#include "logger.h"
#include "netutl.h"
#include "node.h"
#include "utils.h"
#include "xalloc.h"

avl_tree_t *edge_weight_tree;   /* Tree with all edges, sorted on weight */

static int edge_compare(const edge_t *a, const edge_t *b) {
	return strcmp(a->to->name, b->to->name);
}

static int edge_weight_compare(const edge_t *a, const edge_t *b) {
	int result;

	result = a->weight - b->weight;

	if(result) {
		return result;
	}

	result = strcmp(a->from->name, b->from->name);

	if(result) {
		return result;
	}

	return strcmp(a->to->name, b->to->name);
}

void init_edges(void) {
	edge_weight_tree = avl_alloc_tree((avl_compare_t) edge_weight_compare, NULL);
}

avl_tree_t *new_edge_tree(void) {
	return avl_alloc_tree((avl_compare_t) edge_compare, (avl_action_t) free_edge);
}

void free_edge_tree(avl_tree_t *edge_tree) {
	avl_delete_tree(edge_tree);
}

void exit_edges(void) {
	avl_delete_tree(edge_weight_tree);
}

/* Creation and deletion of connection elements */

edge_t *new_edge(void) {
	return xmalloc_and_zero(sizeof(edge_t));
}

void free_edge(edge_t *e) {
	sockaddrfree(&e->address);

	free(e);
}

void edge_add(edge_t *e) {
	avl_insert(edge_weight_tree, e);
	avl_insert(e->from->edge_tree, e);

	e->reverse = lookup_edge(e->to, e->from);

	if(e->reverse) {
		e->reverse->reverse = e;
	}
}

void edge_del(edge_t *e) {
	if(e->reverse) {
		e->reverse->reverse = NULL;
	}

	avl_delete(edge_weight_tree, e);
	avl_delete(e->from->edge_tree, e);
}

edge_t *lookup_edge(node_t *from, node_t *to) {
	edge_t v;

	v.from = from;
	v.to = to;

	return avl_search(from->edge_tree, &v);
}

void dump_edges(void) {
	avl_node_t *node, *node2;
	node_t *n;
	edge_t *e;
	char *address;

	logger(LOG_DEBUG, "Edges:");

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;

		for(node2 = n->edge_tree->head; node2; node2 = node2->next) {
			e = node2->data;
			address = sockaddr2hostname(&e->address);
			logger(LOG_DEBUG, " %s to %s at %s options %x weight %d",
			       e->from->name, e->to->name, address, e->options, e->weight);
			free(address);
		}
	}

	logger(LOG_DEBUG, "End of edges.");
}
