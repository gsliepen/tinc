/*
    node.c -- node tree management
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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#include "system.h"

#include "splay_tree.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "utils.h"
#include "xalloc.h"

splay_tree_t *node_tree;			/* Known nodes, sorted by name */
splay_tree_t *node_udp_tree;		/* Known nodes, sorted by address and port */

node_t *myself;

static int node_compare(const node_t *a, const node_t *b) {
	return strcmp(a->name, b->name);
}

static int node_udp_compare(const node_t *a, const node_t *b) {
	int result;

	cp();

	result = sockaddrcmp(&a->address, &b->address);

	if(result)
		return result;

	return (a->name && b->name) ? strcmp(a->name, b->name) : 0;
}

void init_nodes(void) {
	cp();

	node_tree = splay_alloc_tree((splay_compare_t) node_compare, (splay_action_t) free_node);
	node_udp_tree = splay_alloc_tree((splay_compare_t) node_udp_compare, NULL);
}

void exit_nodes(void) {
	cp();

	splay_delete_tree(node_udp_tree);
	splay_delete_tree(node_tree);
}

node_t *new_node(void) {
	node_t *n = xmalloc_and_zero(sizeof *n);

	cp();

	n->subnet_tree = new_subnet_tree();
	n->edge_tree = new_edge_tree();
	n->queue = list_alloc((list_action_t) free);
	n->mtu = MTU;
	n->maxmtu = MTU;

	return n;
}

void free_node(node_t *n) {
	cp();

	if(n->queue)
		list_delete_list(n->queue);

	if(n->subnet_tree)
		free_subnet_tree(n->subnet_tree);

	if(n->edge_tree)
		free_edge_tree(n->edge_tree);

	sockaddrfree(&n->address);

	cipher_close(&n->cipher);
	digest_close(&n->digest);

	event_del(&n->mtuevent);
	
	if(n->hostname)
		free(n->hostname);

	if(n->name)
		free(n->name);

	free(n);
}

void node_add(node_t *n) {
	cp();

	splay_insert(node_tree, n);
}

void node_del(node_t *n) {
	splay_node_t *node, *next;
	edge_t *e;
	subnet_t *s;

	cp();

	for(node = n->subnet_tree->head; node; node = next) {
		next = node->next;
		s = node->data;
		subnet_del(n, s);
	}

	for(node = n->edge_tree->head; node; node = next) {
		next = node->next;
		e = node->data;
		edge_del(e);
	}

	splay_delete(node_tree, n);
}

node_t *lookup_node(char *name) {
	node_t n = {0};

	cp();
	
	n.name = name;

	return splay_search(node_tree, &n);
}

node_t *lookup_node_udp(const sockaddr_t *sa) {
	node_t n = {0};

	cp();

	n.address = *sa;
	n.name = NULL;

	return splay_search(node_udp_tree, &n);
}

int dump_nodes(struct evbuffer *out) {
	splay_node_t *node;
	node_t *n;

	cp();

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;
		if(evbuffer_add_printf(out, _(" %s at %s cipher %d digest %d maclength %d compression %d options %lx status %04x nexthop %s via %s distance %d pmtu %d (min %d max %d)\n"),
			   n->name, n->hostname, cipher_get_nid(&n->cipher),
			   digest_get_nid(&n->digest), n->maclength, n->compression,
			   n->options, *(uint32_t *)&n->status, n->nexthop ? n->nexthop->name : "-",
			   n->via ? n->via->name : "-", n->distance, n->mtu, n->minmtu, n->maxmtu) == -1)
			return errno;
	}

	return 0;
}
