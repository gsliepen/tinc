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
#include "logger.h"
#include "net.h"
#include "rsa.h"
#include "utils.h"
#include "xalloc.h"

list_t connection_list = {
	.head = NULL,
	.tail = NULL,
	.count = 0,
	.delete = (list_action_t) free_connection,
};

connection_t *everyone;

void init_connections(void) {
	everyone = new_connection();
	everyone->name = xstrdup("everyone");
	everyone->hostname = xstrdup("BROADCAST");
}

void exit_connections(void) {
	list_empty_list(&connection_list);

	free_connection(everyone);
	everyone = NULL;
}

connection_t *new_connection(void) {
	return xzalloc(sizeof(connection_t));
}

#ifndef DISABLE_LEGACY
bool init_crypto_by_nid(legacy_crypto_t *c, nid_t cipher, nid_t digest) {
	if(!cipher_open_by_nid(&c->cipher, cipher)) {
		return false;
	}

	if(!digest_open_by_nid(&c->digest, digest, DIGEST_ALGO_SIZE)) {
		cipher_close(&c->cipher);
		return false;
	}

	c->budget = cipher_budget(&c->cipher);
	return true;
}

bool init_crypto_by_name(legacy_crypto_t *c, const char *cipher, const char *digest) {
	if(!cipher_open_by_name(&c->cipher, cipher)) {
		return false;
	}

	if(!digest_open_by_name(&c->digest, digest, DIGEST_ALGO_SIZE)) {
		cipher_close(&c->cipher);
		return false;
	}

	c->budget = cipher_budget(&c->cipher);
	return true;
}

bool decrease_budget(legacy_crypto_t *c, size_t bytes) {
	if(bytes > c->budget) {
		return false;
	} else {
		c->budget -= bytes;
		return true;
	}
}

static void close_legacy_crypto(legacy_crypto_t *c) {
	cipher_close(&c->cipher);
	digest_close(&c->digest);
}

legacy_ctx_t *new_legacy_ctx(rsa_t *rsa) {
	legacy_ctx_t *ctx = xzalloc(sizeof(legacy_ctx_t));
	ctx->rsa = rsa;
	return ctx;
}

void free_legacy_ctx(legacy_ctx_t *ctx) {
	if(ctx) {
		close_legacy_crypto(&ctx->in);
		close_legacy_crypto(&ctx->out);
		rsa_free(ctx->rsa);
		free(ctx);
	}
}
#endif

void free_connection(connection_t *c) {
	if(!c) {
		return;
	}

#ifndef DISABLE_LEGACY
	free_legacy_ctx(c->legacy);
#endif

	sptps_stop(&c->sptps);
	ecdsa_free(c->ecdsa);

	free(c->hischallenge);
	free(c->mychallenge);

	buffer_clear(&c->inbuf);
	buffer_clear(&c->outbuf);

	io_del(&c->io);

	if(c->socket > 0) {
		if(c->status.tarpit) {
			tarpit(c->socket);
		} else {
			closesocket(c->socket);
		}
	}

	free(c->name);
	free(c->hostname);

	if(c->config_tree) {
		exit_configuration(c->config_tree);
		c->config_tree = NULL;
	}

	free(c);
}

void connection_add(connection_t *c) {
	list_insert_tail(&connection_list, c);
}

void connection_del(connection_t *c) {
	list_delete(&connection_list, c);
}

bool dump_connections(connection_t *cdump) {
	for list_each(connection_t, c, &connection_list) {
		send_request(cdump, "%d %d %s %s %x %d %x",
		             CONTROL, REQ_DUMP_CONNECTIONS,
		             c->name, c->hostname, c->options, c->socket,
		             c->status.value);
	}

	return send_request(cdump, "%d %d", CONTROL, REQ_DUMP_CONNECTIONS);
}
