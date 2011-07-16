/*
    node.c -- node tree management
    Copyright (C) 2001-2011 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "system.h"

#include "control_common.h"
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

	result = sockaddrcmp(&a->address, &b->address);

	if(result)
		return result;

	return (a->name && b->name) ? strcmp(a->name, b->name) : 0;
}

void init_nodes(void) {
	node_tree = splay_alloc_tree((splay_compare_t) node_compare, (splay_action_t) free_node);
	node_udp_tree = splay_alloc_tree((splay_compare_t) node_udp_compare, NULL);
}

void exit_nodes(void) {
	splay_delete_tree(node_udp_tree);
	splay_delete_tree(node_tree);
}

node_t *new_node(void) {
	node_t *n = xmalloc_and_zero(sizeof *n);

	if(replaywin) n->late = xmalloc_and_zero(replaywin);
	n->subnet_tree = new_subnet_tree();
	n->edge_tree = new_edge_tree();
	n->mtu = MTU;
	n->maxmtu = MTU;

	return n;
}

void free_node(node_t *n) {
	if(n->subnet_tree)
		free_subnet_tree(n->subnet_tree);

	if(n->edge_tree)
		free_edge_tree(n->edge_tree);

	sockaddrfree(&n->address);

	cipher_close(&n->incipher);
	digest_close(&n->indigest);
	cipher_close(&n->outcipher);
	digest_close(&n->outdigest);

	ecdh_free(&n->ecdh);
	ecdsa_free(&n->ecdsa);

	if(timeout_initialized(&n->mtuevent))
		event_del(&n->mtuevent);
	
	if(n->hostname)
		free(n->hostname);

	if(n->name)
		free(n->name);

	if(n->late)
		free(n->late);

	free(n);
}

void node_add(node_t *n) {
	splay_insert(node_tree, n);
}

void node_del(node_t *n) {
	splay_node_t *node, *next;
	edge_t *e;
	subnet_t *s;

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

	splay_delete(node_udp_tree, n);
	splay_delete(node_tree, n);
}

node_t *lookup_node(char *name) {
	node_t n = {NULL};

	n.name = name;

	return splay_search(node_tree, &n);
}

node_t *lookup_node_udp(const sockaddr_t *sa) {
	node_t n = {NULL};

	n.address = *sa;
	n.name = NULL;

	return splay_search(node_udp_tree, &n);
}

void update_node_udp(node_t *n, const sockaddr_t *sa) {
	if(n == myself) {
		logger(LOG_WARNING, "Trying to update UDP address of myself!");
		return;
	}

	splay_delete(node_udp_tree, n);

	if(n->hostname)
		free(n->hostname);

	if(sa) {
		n->address = *sa;
		n->hostname = sockaddr2hostname(&n->address);
		splay_insert(node_udp_tree, n);
		ifdebug(PROTOCOL) logger(LOG_DEBUG, "UDP address of %s set to %s", n->name, n->hostname);
	} else {
		memset(&n->address, 0, sizeof n->address);
		n->hostname = NULL;
		ifdebug(PROTOCOL) logger(LOG_DEBUG, "UDP address of %s cleared", n->name);
	}
}

bool dump_nodes(connection_t *c) {
	splay_node_t *node;
	node_t *n;

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;
		send_request(c, "%d %d %s at %s cipher %d digest %d maclength %d compression %d options %x status %04x nexthop %s via %s distance %d pmtu %hd (min %hd max %hd)", CONTROL, REQ_DUMP_NODES,
			   n->name, n->hostname, cipher_get_nid(&n->outcipher),
			   digest_get_nid(&n->outdigest), (int)digest_length(&n->outdigest), n->outcompression,
			   n->options, bitfield_to_int(&n->status, sizeof n->status), n->nexthop ? n->nexthop->name : "-",
			   n->via ? n->via->name ?: "-" : "-", n->distance, n->mtu, n->minmtu, n->maxmtu);
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_NODES);
}

bool dump_traffic(connection_t *c) {
	splay_node_t *node;
	node_t *n;

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;
		send_request(c, "%d %d %s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64, CONTROL, REQ_DUMP_TRAFFIC,
			   n->name, n->in_packets, n->in_bytes, n->out_packets, n->out_bytes);
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_TRAFFIC);
}
