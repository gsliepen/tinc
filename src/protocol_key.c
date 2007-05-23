/*
    protocol_key.c -- handle the meta-protocol, key exchange
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2006 Guus Sliepen <guus@tinc-vpn.org>

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
#include "cipher.h"
#include "connection.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

static bool mykeyused = false;

bool send_key_changed(connection_t *c, const node_t *n) {
	cp();

	/* Only send this message if some other daemon requested our key previously.
	   This reduces unnecessary key_changed broadcasts.
	 */

	if(n == myself && !mykeyused)
		return true;

	return send_request(c, "%d %lx %s", KEY_CHANGED, random(), n->name);
}

bool key_changed_h(connection_t *c, char *request) {
	char name[MAX_STRING_SIZE];
	node_t *n;

	cp();

	if(sscanf(request, "%*d %*x " MAX_STRING, name) != 1) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "KEY_CHANGED",
			   c->name, c->hostname);
		return false;
	}

	if(seen_request(request))
		return true;

	n = lookup_node(name);

	if(!n) {
		logger(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist"),
			   "KEY_CHANGED", c->name, c->hostname, name);
		return false;
	}

	n->status.validkey = false;
	n->status.waitingforkey = false;

	/* Tell the others */

	if(!tunnelserver)
		forward_request(c, request);

	return true;
}

bool send_req_key(connection_t *c, const node_t *from, const node_t *to) {
	cp();

	return send_request(c, "%d %s %s", REQ_KEY, from->name, to->name);
}

bool req_key_h(connection_t *c, char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;

	cp();

	if(sscanf(request, "%*d " MAX_STRING " " MAX_STRING, from_name, to_name) != 2) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "REQ_KEY", c->name,
			   c->hostname);
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist in our connection list"),
			   "REQ_KEY", c->name, c->hostname, from_name);
		return false;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, _("Got %s from %s (%s) destination %s which does not exist in our connection list"),
			   "REQ_KEY", c->name, c->hostname, to_name);
		return false;
	}

	/* Check if this key request is for us */

	if(to == myself) {			/* Yes, send our own key back */
		mykeyused = true;
		from->received_seqno = 0;
		memset(from->late, 0, sizeof(from->late));
		send_ans_key(c, myself, from);
	} else {
		if(tunnelserver)
			return false;

		send_req_key(to->nexthop->connection, from, to);
	}

	return true;
}

bool send_ans_key(connection_t *c, const node_t *from, const node_t *to) {
	size_t keylen = cipher_keylength(&from->cipher);
	char key[keylen];

	cp();

	cipher_get_key(&from->cipher, key);
	bin2hex(key, key, keylen);
	key[keylen * 2] = '\0';

	return send_request(c, "%d %s %s %s %d %d %d %d", ANS_KEY,
						from->name, to->name, key,
						cipher_get_nid(&from->cipher),
						digest_get_nid(&from->digest), from->maclength,
						from->compression);
}

bool ans_key_h(connection_t *c, char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char key[MAX_STRING_SIZE];
	int cipher, digest, maclength, compression;
	node_t *from, *to;

	cp();

	if(sscanf(request, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" %d %d %d %d",
		from_name, to_name, key, &cipher, &digest, &maclength,
		&compression) != 7) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "ANS_KEY", c->name,
			   c->hostname);
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist in our connection list"),
			   "ANS_KEY", c->name, c->hostname, from_name);
		return false;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, _("Got %s from %s (%s) destination %s which does not exist in our connection list"),
			   "ANS_KEY", c->name, c->hostname, to_name);
		return false;
	}

	/* Forward it if necessary */

	if(to != myself) {
		if(tunnelserver)
			return false;

		return send_request(to->nexthop->connection, "%s", request);
	}

	/* Check and lookup cipher and digest algorithms */

	if(!cipher_open_by_nid(&from->cipher, cipher)) {
		logger(LOG_ERR, _("Node %s (%s) uses unknown cipher!"), from->name, from->hostname);
		return false;
	}

	if(strlen(key) / 2 != cipher_keylength(&from->cipher)) {
		logger(LOG_ERR, _("Node %s (%s) uses wrong keylength!"), from->name, from->hostname);
		return false;
	}

	from->maclength = maclength;

	if(!digest_open_by_nid(&from->digest, digest)) {
		logger(LOG_ERR, _("Node %s (%s) uses unknown digest!"), from->name, from->hostname);
		return false;
	}

	if(from->maclength > digest_length(&from->digest) || from->maclength < 0) {
		logger(LOG_ERR, _("Node %s (%s) uses bogus MAC length!"), from->name, from->hostname);
		return false;
	}

	if(compression < 0 || compression > 11) {
		logger(LOG_ERR, _("Node %s (%s) uses bogus compression level!"), from->name, from->hostname);
		return false;
	}
	
	from->compression = compression;

	/* Update our copy of the origin's packet key */

	hex2bin(key, key, cipher_keylength(&from->cipher));
	cipher_set_key(&from->cipher, key, false);

	from->status.validkey = true;
	from->status.waitingforkey = false;
	from->sent_seqno = 0;

	if(from->options & OPTION_PMTU_DISCOVERY && !from->mtuprobes)
		send_mtu_probe(from);

	flush_queue(from);

	return true;
}
