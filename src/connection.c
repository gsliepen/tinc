/*
    connection.c -- connection list management
    Copyright (C) 2000-2009 Guus Sliepen <guus@tinc-vpn.org>,
                  2000-2005 Ivo Timmermans
                  2008      Max Rijevski <maksuf@gmail.com>

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
#include "cipher.h"
#include "conf.h"
#include "control_common.h"
#include "list.h"
#include "logger.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

splay_tree_t *connection_tree;	/* Meta connections */
connection_t *broadcast;

static int connection_compare(const connection_t *a, const connection_t *b) {
	return a < b ? -1 : a == b ? 0 : 1;
}

void init_connections(void) {
	connection_tree = splay_alloc_tree((splay_compare_t) connection_compare, (splay_action_t) free_connection);
	broadcast = new_connection();
	broadcast->name = xstrdup("everyone");
	broadcast->hostname = xstrdup("BROADCAST");
}

void exit_connections(void) {
	splay_delete_tree(connection_tree);
	free_connection(broadcast);
}

connection_t *new_connection(void) {
	return xmalloc_and_zero(sizeof(connection_t));
}

void free_connection(connection_t *c) {
	if(!c)
		return;

	if(c->name)
		free(c->name);

	if(c->hostname)
		free(c->hostname);

	cipher_close(&c->incipher);
	digest_close(&c->indigest);
	cipher_close(&c->outcipher);
	digest_close(&c->outdigest);

	ecdh_free(&c->ecdh);
	ecdsa_free(&c->ecdsa);
	rsa_free(&c->rsa);

	if(c->hischallenge)
		free(c->hischallenge);

	if(c->config_tree)
		exit_configuration(&c->config_tree);

	buffer_clear(&c->inbuf);
	buffer_clear(&c->outbuf);
	
	if(event_initialized(&c->inevent))
		event_del(&c->inevent);

	if(event_initialized(&c->outevent))
		event_del(&c->outevent);

	if(c->socket > 0)
		closesocket(c->socket);

	free(c);
}

void connection_add(connection_t *c) {
	splay_insert(connection_tree, c);
}

void connection_del(connection_t *c) {
	splay_delete(connection_tree, c);
}

bool dump_connections(connection_t *cdump) {
	splay_node_t *node;
	connection_t *c;

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;
		send_request(cdump, "%d %d %s at %s options %x socket %d status %04x",
				CONTROL, REQ_DUMP_CONNECTIONS,
				c->name, c->hostname, c->options, c->socket,
				bitfield_to_int(&c->status, sizeof c->status));
	}

	return send_request(cdump, "%d %d", CONTROL, REQ_DUMP_CONNECTIONS);
}
