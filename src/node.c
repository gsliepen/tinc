/*
    node.c -- node tree management
    Copyright (C) 2001-2013 Guus Sliepen <guus@tinc-vpn.org>,
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
#include "hash.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "splay_tree.h"
#include "utils.h"
#include "xalloc.h"

#include "ed25519/sha512.h"

splay_tree_t *node_tree;
static splay_tree_t *node_id_tree;
static splay_tree_t *node_udp_tree;

node_t *myself;

static int node_compare(const node_t *a, const node_t *b) {
	return strcmp(a->name, b->name);
}

static int node_id_compare(const node_t *a, const node_t *b) {
	return memcmp(&a->id, &b->id, sizeof(node_id_t));
}

static int node_udp_compare(const node_t *a, const node_t *b) {
	int result = sockaddrcmp(&a->address, &b->address);
	if (result)
		return result;
	return (a->name && b->name) ? strcmp(a->name, b->name) : 0;
}

void init_nodes(void) {
	node_tree = splay_alloc_tree((splay_compare_t) node_compare, (splay_action_t) free_node);
	node_id_tree = splay_alloc_tree((splay_compare_t) node_id_compare, NULL);
	node_udp_tree = splay_alloc_tree((splay_compare_t) node_udp_compare, NULL);
}

void exit_nodes(void) {
	splay_delete_tree(node_udp_tree);
	splay_delete_tree(node_id_tree);
	splay_delete_tree(node_tree);
}

node_t *new_node(void) {
	node_t *n = xzalloc(sizeof *n);

	if(replaywin) n->late = xzalloc(replaywin);
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

#ifndef DISABLE_LEGACY
	cipher_close(n->incipher);
	digest_close(n->indigest);
	cipher_close(n->outcipher);
	digest_close(n->outdigest);
#endif

	ecdsa_free(n->ecdsa);
	sptps_stop(&n->sptps);

	timeout_del(&n->udp_ping_timeout);

	if(n->hostname)
		free(n->hostname);

	if(n->name)
		free(n->name);

	if(n->late)
		free(n->late);

	free(n);
}

void node_add(node_t *n) {
	unsigned char buf[64];
	sha512(n->name, strlen(n->name),buf);
	memcpy(&n->id, buf, sizeof n->id);

	splay_insert(node_tree, n);
	splay_insert(node_id_tree, n);
}

void node_del(node_t *n) {
	splay_delete(node_udp_tree, n);

	for splay_each(subnet_t, s, n->subnet_tree)
		subnet_del(n, s);

	for splay_each(edge_t, e, n->edge_tree)
		edge_del(e);

	splay_delete(node_id_tree, n);
	splay_delete(node_tree, n);
}

node_t *lookup_node(char *name) {
	node_t n = {NULL};

	n.name = name;

	return splay_search(node_tree, &n);
}

node_t *lookup_node_id(const node_id_t *id) {
	node_t n = {.id = *id};
	return splay_search(node_id_tree, &n);
}

node_t *lookup_node_udp(const sockaddr_t *sa) {
	node_t tmp = {.address = *sa};
	return splay_search(node_udp_tree, &tmp);
}

void update_node_udp(node_t *n, const sockaddr_t *sa) {
	if(n == myself) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Trying to update UDP address of myself!");
		return;
	}

	splay_delete(node_udp_tree, n);

	if(sa) {
		n->address = *sa;
		n->sock = 0;
		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
				n->sock = i;
				break;
			}
		}
		splay_insert(node_udp_tree, n);
		free(n->hostname);
		n->hostname = sockaddr2hostname(&n->address);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "UDP address of %s set to %s", n->name, n->hostname);
	}

	/* invalidate UDP information - note that this is a security feature as well to make sure
	   we can't be tricked into flooding any random address with UDP packets */
	n->status.udp_confirmed = false;
	n->maxrecentlen = 0;
	n->mtuprobes = 0;
	n->minmtu = 0;
	n->maxmtu = MTU;
}

bool dump_nodes(connection_t *c) {
	for splay_each(node_t, n, node_tree) {
		char id[2 * sizeof n->id + 1];
		for (size_t c = 0; c < sizeof n->id; ++c)
			snprintf(id + 2 * c, 3, "%02x", n->id.x[c]);
		id[sizeof id - 1] = 0;
		send_request(c, "%d %d %s %s %s %d %d %d %d %x %x %s %s %d %d %d %d %ld", CONTROL, REQ_DUMP_NODES,
			   n->name, id, n->hostname ?: "unknown port unknown",
#ifdef DISABLE_LEGACY
			   0, 0, 0,
#else
			   cipher_get_nid(n->outcipher), digest_get_nid(n->outdigest), (int)digest_length(n->outdigest),
#endif
			   n->outcompression, n->options, bitfield_to_int(&n->status, sizeof n->status),
			   n->nexthop ? n->nexthop->name : "-", n->via ? n->via->name ?: "-" : "-", n->distance,
			   n->mtu, n->minmtu, n->maxmtu, (long)n->last_state_change);
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_NODES);
}

bool dump_traffic(connection_t *c) {
	for splay_each(node_t, n, node_tree)
		send_request(c, "%d %d %s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64, CONTROL, REQ_DUMP_TRAFFIC,
			   n->name, n->in_packets, n->in_bytes, n->out_packets, n->out_bytes);

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_TRAFFIC);
}
