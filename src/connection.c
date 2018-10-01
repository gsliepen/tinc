/*
    connection.c -- connection list management
    Copyright (C) 2000-2016 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "avl_tree.h"
#include "conf.h"
#include "logger.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

avl_tree_t *connection_tree;    /* Meta connections */
connection_t *everyone;

static int connection_compare(const connection_t *a, const connection_t *b) {
	return a < b ? -1 : a == b ? 0 : 1;
}

void init_connections(void) {
	connection_tree = avl_alloc_tree((avl_compare_t) connection_compare, (avl_action_t) free_connection);
	everyone = new_connection();
	everyone->name = xstrdup("everyone");
	everyone->hostname = xstrdup("BROADCAST");
}

void exit_connections(void) {
	avl_delete_tree(connection_tree);
	free_connection(everyone);
}

connection_t *new_connection(void) {
	connection_t *c;

	c = xmalloc_and_zero(sizeof(connection_t));

	if(!c) {
		return NULL;
	}

	gettimeofday(&c->start, NULL);

	return c;
}

void free_connection_partially(connection_t *c) {
	free(c->inkey);
	free(c->outkey);
	free(c->mychallenge);
	free(c->hischallenge);
	free(c->outbuf);

	c->inkey = NULL;
	c->outkey = NULL;
	c->mychallenge = NULL;
	c->hischallenge = NULL;
	c->outbuf = NULL;

	c->status.pinged = false;
	c->status.active = false;
	c->status.connecting = false;
	c->status.timeout = false;
	c->status.encryptout = false;
	c->status.decryptin = false;
	c->status.mst = false;

	c->options = 0;
	c->buflen = 0;
	c->reqlen = 0;
	c->tcplen = 0;
	c->allow_request = 0;
	c->outbuflen = 0;
	c->outbufsize = 0;
	c->outbufstart = 0;
	c->last_ping_time = 0;
	c->last_flushed_time = 0;
	c->inbudget = 0;
	c->outbudget = 0;

	if(c->inctx) {
		EVP_CIPHER_CTX_cleanup(c->inctx);
		free(c->inctx);
		c->inctx = NULL;
	}

	if(c->outctx) {
		EVP_CIPHER_CTX_cleanup(c->outctx);
		free(c->outctx);
		c->outctx = NULL;
	}

	if(c->rsa_key) {
		RSA_free(c->rsa_key);
		c->rsa_key = NULL;
	}
}

void free_connection(connection_t *c) {
	free_connection_partially(c);

	free(c->name);
	free(c->hostname);

	if(c->config_tree) {
		exit_configuration(&c->config_tree);
	}

	free(c);
}

void connection_add(connection_t *c) {
	avl_insert(connection_tree, c);
}

void connection_del(connection_t *c) {
	avl_delete(connection_tree, c);
}

void dump_connections(void) {
	avl_node_t *node;
	connection_t *c;

	logger(LOG_DEBUG, "Connections:");

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;
		logger(LOG_DEBUG, " %s at %s options %x socket %d status %04x outbuf %d/%d/%d",
		       c->name, c->hostname, c->options, c->socket, bitfield_to_int(&c->status, sizeof(c->status)),
		       c->outbufsize, c->outbufstart, c->outbuflen);
	}

	logger(LOG_DEBUG, "End of connections.");
}
