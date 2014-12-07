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

static digest_t *sha256;

splay_tree_t *node_tree;
static splay_tree_t *node_id_tree;
static hash_t *node_udp_cache;
static hash_t *node_id_cache;

node_t *myself;

static int node_compare(const node_t *a, const node_t *b) {
	return strcmp(a->name, b->name);
}

static int node_id_compare(const node_t *a, const node_t *b) {
	return memcmp(&a->id, &b->id, sizeof(node_id_t));
}

void init_nodes(void) {
	sha256 = digest_open_by_name("sha256", sizeof(node_id_t));

	node_tree = splay_alloc_tree((splay_compare_t) node_compare, (splay_action_t) free_node);
	node_id_tree = splay_alloc_tree((splay_compare_t) node_id_compare, NULL);
	node_udp_cache = hash_alloc(0x100, sizeof(sockaddr_t));
	node_id_cache = hash_alloc(0x100, sizeof(node_id_t));
}

void exit_nodes(void) {
	hash_free(node_id_cache);
	hash_free(node_udp_cache);
	splay_delete_tree(node_id_tree);
	splay_delete_tree(node_tree);

	digest_close(sha256);
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

	cipher_close(n->incipher);
	digest_close(n->indigest);
	cipher_close(n->outcipher);
	digest_close(n->outdigest);

	ecdsa_free(n->ecdsa);
	sptps_stop(&n->sptps);

	timeout_del(&n->mtutimeout);

	if(n->hostname)
		free(n->hostname);

	if(n->name)
		free(n->name);

	if(n->late)
		free(n->late);

	free(n);
}

void node_add(node_t *n) {
	digest_create(sha256, n->name, strlen(n->name), &n->id);

	splay_insert(node_tree, n);
	splay_insert(node_id_tree, n);
}

void node_del(node_t *n) {
	hash_delete(node_udp_cache, &n->address);
	hash_delete(node_id_cache, &n->id);

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
	node_t *n = hash_search(node_id_cache, id);
	if(!n) {
		node_t tmp = {.id = *id};
		n = splay_search(node_id_tree, &tmp);
		if(n)
			hash_insert(node_id_cache, id, n);
	}

	return n;
}

node_t *lookup_node_udp(const sockaddr_t *sa) {
	return hash_search(node_udp_cache, sa);
}

void update_node_udp(node_t *n, const sockaddr_t *sa) {
	if(n == myself) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Trying to update UDP address of myself!");
		return;
	}

	hash_delete(node_udp_cache, &n->address);

	if(sa) {
		n->address = *sa;
		n->sock = 0;
		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
				n->sock = i;
				break;
			}
		}
		hash_insert(node_udp_cache, sa, n);
		free(n->hostname);
		n->hostname = sockaddr2hostname(&n->address);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "UDP address of %s set to %s", n->name, n->hostname);
	}

	/* invalidate UDP information - note that this is a security feature as well to make sure
	   we can't be tricked into flooding any random address with UDP packets */
	n->status.udp_confirmed = false;
	n->mtuprobes = 0;
	n->minmtu = 0;
	n->maxmtu = MTU;
}

bool dump_nodes(connection_t *c) {
	for splay_each(node_t, n, node_tree) {
		char id[2 * sizeof n->id + 1];
		for (size_t c = 0; c < sizeof n->id; ++c)
			sprintf(id + 2 * c, "%02hhx", n->id.x[c]);
		id[sizeof id - 1] = 0;
		send_request(c, "%d %d %s %s %s %d %d %d %d %x %x %s %s %d %hd %hd %hd %ld", CONTROL, REQ_DUMP_NODES,
			   n->name, id, n->hostname ?: "unknown port unknown", cipher_get_nid(n->outcipher),
			   digest_get_nid(n->outdigest), (int)digest_length(n->outdigest), n->outcompression,
			   n->options, bitfield_to_int(&n->status, sizeof n->status), n->nexthop ? n->nexthop->name : "-",
			   n->via ? n->via->name ?: "-" : "-", n->distance, n->mtu, n->minmtu, n->maxmtu, (long)n->last_state_change);
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_NODES);
}

bool dump_traffic(connection_t *c) {
	for splay_each(node_t, n, node_tree)
		send_request(c, "%d %d %s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64, CONTROL, REQ_DUMP_TRAFFIC,
			   n->name, n->in_packets, n->in_bytes, n->out_packets, n->out_bytes);

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_TRAFFIC);
}
