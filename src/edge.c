/*
    edge.c -- edge tree management
    Copyright (C) 2000-2021 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "splay_tree.h"
#include "control_common.h"
#include "edge.h"
#include "logger.h"
#include "netutl.h"
#include "node.h"
#include "xalloc.h"

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

splay_tree_t edge_weight_tree = {
	.compare = (splay_compare_t) edge_weight_compare,
};

static int edge_compare(const edge_t *a, const edge_t *b) {
	return strcmp(a->to->name, b->to->name);
}

void init_edge_tree(splay_tree_t *tree) {
	memset(tree, 0, sizeof(*tree));
	tree->compare = (splay_compare_t) edge_compare;
	tree->delete = (splay_action_t) free_edge;
}

void exit_edges(void) {
	splay_empty_tree(&edge_weight_tree);
}

/* Creation and deletion of connection elements */

edge_t *new_edge(void) {
	return xzalloc(sizeof(edge_t));
}

void free_edge(edge_t *e) {
	if(e) {
		sockaddrfree(&e->address);
		sockaddrfree(&e->local_address);

		free(e);
	}
}

void edge_add(edge_t *e) {
	splay_node_t *node = splay_insert(&e->from->edge_tree, e);

	if(!node) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Edge from %s to %s already exists in edge_tree\n", e->from->name, e->to->name);
		return;
	}


	e->reverse = lookup_edge(e->to, e->from);

	if(e->reverse) {
		e->reverse->reverse = e;
	}

	node = splay_insert(&edge_weight_tree, e);

	if(!node) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Edge from %s to %s already exists in edge_weight_tree\n", e->from->name, e->to->name);
		return;
	}
}

void edge_del(edge_t *e) {
	if(e->reverse) {
		e->reverse->reverse = NULL;
	}

	splay_delete(&edge_weight_tree, e);
	splay_delete(&e->from->edge_tree, e);
}

edge_t *lookup_edge(node_t *from, node_t *to) {
	edge_t v;

	v.from = from;
	v.to = to;

	return splay_search(&from->edge_tree, &v);
}

bool dump_edges(connection_t *c) {
	for splay_each(node_t, n, &node_tree) {
		for splay_each(edge_t, e, &n->edge_tree) {
			char *address = sockaddr2hostname(&e->address);
			char *local_address = sockaddr2hostname(&e->local_address);
			send_request(c, "%d %d %s %s %s %s %x %d",
			             CONTROL, REQ_DUMP_EDGES,
			             e->from->name, e->to->name, address,
			             local_address, e->options, e->weight);
			free(address);
			free(local_address);
		}
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_EDGES);
}
