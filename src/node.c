/*
    node.c -- node tree management
    Copyright (C) 2001-2009 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "avl_tree.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "utils.h"
#include "xalloc.h"

avl_tree_t *node_tree;			/* Known nodes, sorted by name */
avl_tree_t *node_udp_tree;		/* Known nodes, sorted by address and port */

node_t *myself;

static int node_compare(const node_t *a, const node_t *b)
{
	return strcmp(a->name, b->name);
}

static int node_udp_compare(const node_t *a, const node_t *b)
{
	int result;

	cp();

	result = sockaddrcmp(&a->address, &b->address);

	if(result)
		return result;

	return (a->name && b->name) ? strcmp(a->name, b->name) : 0;
}

void init_nodes(void)
{
	cp();

	node_tree = avl_alloc_tree((avl_compare_t) node_compare, (avl_action_t) free_node);
	node_udp_tree = avl_alloc_tree((avl_compare_t) node_udp_compare, NULL);
}

void exit_nodes(void)
{
	cp();

	avl_delete_tree(node_udp_tree);
	avl_delete_tree(node_tree);
}

node_t *new_node(void)
{
	node_t *n = xmalloc_and_zero(sizeof(*n));

	cp();

	n->subnet_tree = new_subnet_tree();
	n->edge_tree = new_edge_tree();
	EVP_CIPHER_CTX_init(&n->packet_ctx);
	n->mtu = MTU;
	n->maxmtu = MTU;

	return n;
}

void free_node(node_t *n)
{
	cp();

	if(n->key)
		free(n->key);

	if(n->subnet_tree)
		free_subnet_tree(n->subnet_tree);

	if(n->edge_tree)
		free_edge_tree(n->edge_tree);

	sockaddrfree(&n->address);

	EVP_CIPHER_CTX_cleanup(&n->packet_ctx);

	if(n->mtuevent)
		event_del(n->mtuevent);
	
	if(n->hostname)
		free(n->hostname);

	if(n->name)
		free(n->name);

	free(n);
}

void node_add(node_t *n)
{
	cp();

	avl_insert(node_tree, n);
}

void node_del(node_t *n)
{
	avl_node_t *node, *next;
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

	avl_delete(node_tree, n);
}

node_t *lookup_node(char *name)
{
	node_t n = {0};

	cp();
	
	n.name = name;

	return avl_search(node_tree, &n);
}

node_t *lookup_node_udp(const sockaddr_t *sa)
{
	node_t n = {0};

	cp();

	n.address = *sa;
	n.name = NULL;

	return avl_search(node_udp_tree, &n);
}

void dump_nodes(void)
{
	avl_node_t *node;
	node_t *n;

	cp();

	logger(LOG_DEBUG, _("Nodes:"));

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;
		logger(LOG_DEBUG, _(" %s at %s cipher %d digest %d maclength %d compression %d options %lx status %04x nexthop %s via %s pmtu %d (min %d max %d)"),
			   n->name, n->hostname, n->cipher ? n->cipher->nid : 0,
			   n->digest ? n->digest->type : 0, n->maclength, n->compression,
			   n->options, *(uint32_t *)&n->status, n->nexthop ? n->nexthop->name : "-",
			   n->via ? n->via->name : "-", n->mtu, n->minmtu, n->maxmtu);
	}

	logger(LOG_DEBUG, _("End of nodes."));
}
