/*
    protocol_key.c -- handle the meta-protocol, key exchange
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "avl_tree.h"
#include "connection.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool mykeyused = false;

bool send_key_changed() {
	/* Only send this message if some other daemon requested our key previously.
	   This reduces unnecessary key_changed broadcasts.
	 */

	if(!mykeyused)
		return true;

	return send_request(broadcast, "%d %x %s", KEY_CHANGED, rand(), myself->name);
}

bool key_changed_h(connection_t *c) {
	char name[MAX_STRING_SIZE];
	node_t *n;

	if(sscanf(c->buffer, "%*d %*x " MAX_STRING, name) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "KEY_CHANGED",
			   c->name, c->hostname);
		return false;
	}

	if(seen_request(c->buffer))
		return true;

	n = lookup_node(name);

	if(!n) {
		logger(LOG_ERR, "Got %s from %s (%s) origin %s which does not exist",
			   "KEY_CHANGED", c->name, c->hostname, name);
		return false;
	}

	n->status.validkey = false;
	n->status.waitingforkey = false;

	/* Tell the others */

	if(!tunnelserver)
		forward_request(c);

	return true;
}

bool send_req_key(node_t *to) {
	return send_request(to->nexthop->connection, "%d %s %s", REQ_KEY, myself->name, to->name);
}

bool req_key_h(connection_t *c) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;

	if(sscanf(c->buffer, "%*d " MAX_STRING " " MAX_STRING, from_name, to_name) != 2) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "REQ_KEY", c->name,
			   c->hostname);
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
			   "REQ_KEY", c->name, c->hostname, from_name);
		return false;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
			   "REQ_KEY", c->name, c->hostname, to_name);
		return false;
	}

	/* Check if this key request is for us */

	if(to == myself) {			/* Yes, send our own key back */
		send_ans_key(from);
	} else {
		if(tunnelserver)
			return false;

		if(!to->status.reachable) {
			logger(LOG_WARNING, "Got %s from %s (%s) destination %s which is not reachable",
				"REQ_KEY", c->name, c->hostname, to_name);
			return true;
		}

		send_request(to->nexthop->connection, "%s", c->buffer);
	}

	return true;
}

bool send_ans_key(node_t *to) {
	char *key;

	// Set key parameters
	to->incipher = myself->incipher;
	to->inkeylength = myself->inkeylength;
	to->indigest = myself->indigest;
	to->inmaclength = myself->inmaclength;
	to->incompression = myself->incompression;

	// Allocate memory for key
	to->inkey = xrealloc(to->inkey, to->inkeylength);

	// Create a new key
	RAND_pseudo_bytes((unsigned char *)to->inkey, to->inkeylength);
	if(to->incipher)
		EVP_DecryptInit_ex(&to->inctx, to->incipher, NULL, (unsigned char *)to->inkey, (unsigned char *)to->inkey + to->incipher->key_len);

	// Reset sequence number and late packet window
	mykeyused = true;
	to->received_seqno = 0;
	memset(to->late, 0, sizeof(to->late));

	// Convert to hexadecimal and send
	key = alloca(2 * to->inkeylength + 1);
	bin2hex(to->inkey, key, to->inkeylength);
	key[to->inkeylength * 2] = '\0';

	return send_request(to->nexthop->connection, "%d %s %s %s %d %d %d %d", ANS_KEY,
			myself->name, to->name, key,
			to->incipher ? to->incipher->nid : 0,
			to->indigest ? to->indigest->type : 0, to->inmaclength,
			to->incompression);
}

bool ans_key_h(connection_t *c) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char key[MAX_STRING_SIZE];
	int cipher, digest, maclength, compression;
	node_t *from, *to;

	if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" %d %d %d %d",
		from_name, to_name, key, &cipher, &digest, &maclength,
		&compression) != 7) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ANS_KEY", c->name,
			   c->hostname);
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
			   "ANS_KEY", c->name, c->hostname, from_name);
		return false;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
			   "ANS_KEY", c->name, c->hostname, to_name);
		return false;
	}

	/* Forward it if necessary */

	if(to != myself) {
		if(tunnelserver)
			return false;

		if(!to->status.reachable) {
			logger(LOG_WARNING, "Got %s from %s (%s) destination %s which is not reachable",
				"ANS_KEY", c->name, c->hostname, to_name);
			return true;
		}

		return send_request(to->nexthop->connection, "%s", c->buffer);
	}

	/* Update our copy of the origin's packet key */
	from->outkey = xrealloc(from->outkey, strlen(key) / 2);

	from->outkey = xstrdup(key);
	from->outkeylength = strlen(key) / 2;
	hex2bin(key, from->outkey, from->outkeylength);

	from->status.waitingforkey = false;
	/* Check and lookup cipher and digest algorithms */

	if(cipher) {
		from->outcipher = EVP_get_cipherbynid(cipher);

		if(!from->outcipher) {
			logger(LOG_ERR, "Node %s (%s) uses unknown cipher!", from->name,
				   from->hostname);
			return false;
		}

		if(from->outkeylength != from->outcipher->key_len + from->outcipher->iv_len) {
			logger(LOG_ERR, "Node %s (%s) uses wrong keylength!", from->name,
				   from->hostname);
			return false;
		}
	} else {
		from->outcipher = NULL;
	}

	from->outmaclength = maclength;

	if(digest) {
		from->outdigest = EVP_get_digestbynid(digest);

		if(!from->outdigest) {
			logger(LOG_ERR, "Node %s (%s) uses unknown digest!", from->name,
				   from->hostname);
			return false;
		}

		if(from->outmaclength > from->outdigest->md_size || from->outmaclength < 0) {
			logger(LOG_ERR, "Node %s (%s) uses bogus MAC length!",
				   from->name, from->hostname);
			return false;
		}
	} else {
		from->outdigest = NULL;
	}

	if(compression < 0 || compression > 11) {
		logger(LOG_ERR, "Node %s (%s) uses bogus compression level!", from->name, from->hostname);
		return false;
	}
	
	from->outcompression = compression;

	if(from->outcipher)
		if(!EVP_EncryptInit_ex(&from->outctx, from->outcipher, NULL, (unsigned char *)from->outkey, (unsigned char *)from->outkey + from->outcipher->key_len)) {
			logger(LOG_ERR, "Error during initialisation of key from %s (%s): %s",
					from->name, from->hostname, ERR_error_string(ERR_get_error(), NULL));
			return false;
		}

	from->status.validkey = true;
	from->sent_seqno = 0;

	if(from->options & OPTION_PMTU_DISCOVERY && !from->mtuprobes)
		send_mtu_probe(from);

	return true;
}
