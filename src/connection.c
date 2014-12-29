/*
    connection.c -- connection list management
    Copyright (C) 2000-2013 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "list.h"
#include "cipher.h"
#include "conf.h"
#include "control_common.h"
#include "list.h"
#include "logger.h"
#include "rsa.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

list_t *connection_list;
connection_t *everyone;

void init_connections(void) {
	connection_list = list_alloc((list_action_t) free_connection);
	everyone = new_connection();
	everyone->name = xstrdup("everyone");
	everyone->hostname = xstrdup("BROADCAST");
}

void exit_connections(void) {
	list_delete_list(connection_list);
	free_connection(everyone);
}

connection_t *new_connection(void) {
	return xzalloc(sizeof(connection_t));
}

void free_connection(connection_t *c) {
	if(!c)
		return;

#ifndef DISABLE_LEGACY
	cipher_close(c->incipher);
	digest_close(c->indigest);
	cipher_close(c->outcipher);
	digest_close(c->outdigest);
	rsa_free(c->rsa);
#endif

	sptps_stop(&c->sptps);
	ecdsa_free(c->ecdsa);

	free(c->hischallenge);

	buffer_clear(&c->inbuf);
	buffer_clear(&c->outbuf);

	io_del(&c->io);

	if(c->socket > 0)
		closesocket(c->socket);

	free(c->name);
	free(c->hostname);

	if(c->config_tree)
		exit_configuration(&c->config_tree);

	free(c);
}

void connection_add(connection_t *c) {
	list_insert_tail(connection_list, c);
}

void connection_del(connection_t *c) {
	list_delete(connection_list, c);
}

bool dump_connections(connection_t *cdump) {
	for list_each(connection_t, c, connection_list) {
		send_request(cdump, "%d %d %s %s %x %d %x",
				CONTROL, REQ_DUMP_CONNECTIONS,
				c->name, c->hostname, c->options, c->socket,
				bitfield_to_int(&c->status, sizeof c->status));
	}

	return send_request(cdump, "%d %d", CONTROL, REQ_DUMP_CONNECTIONS);
}
