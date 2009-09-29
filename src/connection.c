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
#include "list.h"
#include "logger.h"
#include "net.h"				/* Don't ask. */
#include "netutl.h"
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
	cipher_close(&c->outcipher);

	if(c->hischallenge)
		free(c->hischallenge);

	if(c->config_tree)
		exit_configuration(&c->config_tree);

	if(c->buffer)
		bufferevent_free(c->buffer);
	
	if(event_initialized(&c->inevent))
		event_del(&c->inevent);

	free(c);
}

void connection_add(connection_t *c) {
	splay_insert(connection_tree, c);
}

void connection_del(connection_t *c) {
	splay_delete(connection_tree, c);
}

int dump_connections(struct evbuffer *out) {
	splay_node_t *node;
	connection_t *c;

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;
		if(evbuffer_add_printf(out,
				   " %s at %s options %lx socket %d status %04x\n",
				   c->name, c->hostname, c->options, c->socket,
				   bitfield_to_int(&c->status, sizeof c->status)) == -1)
			return errno;
	}

	return 0;
}

bool read_connection_config(connection_t *c) {
	char *fname;
	int x;

	xasprintf(&fname, "%s/hosts/%s", confbase, c->name);
	x = read_config_file(c->config_tree, fname);
	free(fname);

	return x == 0;
}
