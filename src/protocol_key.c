/*
    protocol_key.c -- handle the meta-protocol, key exchange
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2016 Guus Sliepen <guus@tinc-vpn.org>

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

static bool mykeyused = false;

void send_key_changed(void) {
	avl_node_t *node;
	connection_t *c;

	send_request(everyone, "%d %x %s", KEY_CHANGED, rand(), myself->name);

	/* Immediately send new keys to directly connected nodes to keep UDP mappings alive */

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;

		if(c->status.active && c->node && c->node->status.reachable) {
			send_ans_key(c->node);
		}
	}
}

bool key_changed_h(connection_t *c) {
	char name[MAX_STRING_SIZE];
	node_t *n;

	if(sscanf(c->buffer, "%*d %*x " MAX_STRING, name) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "KEY_CHANGED",
		       c->name, c->hostname);
		return false;
	}

	if(!check_id(name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "KEY_CHANGED", c->name, c->hostname, "invalid name");
		return false;
	}

	if(seen_request(c->buffer)) {
		return true;
	}

	n = lookup_node(name);

	if(!n) {
		logger(LOG_ERR, "Got %s from %s (%s) origin %s which does not exist",
		       "KEY_CHANGED", c->name, c->hostname, name);
		return true;
	}

	n->status.validkey = false;
	n->last_req_key = 0;

	/* Tell the others */

	if(!tunnelserver) {
		forward_request(c);
	}

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

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "REQ_KEY", c->name, c->hostname, "invalid name");
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
		       "REQ_KEY", c->name, c->hostname, from_name);
		return true;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
		       "REQ_KEY", c->name, c->hostname, to_name);
		return true;
	}

	/* Check if this key request is for us */

	if(to == myself) {                      /* Yes, send our own key back */
		if(!send_ans_key(from)) {
			return false;
		}
	} else {
		if(tunnelserver) {
			return true;
		}

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
	// Set key parameters
	to->incipher = myself->incipher;
	to->inkeylength = myself->inkeylength;
	to->indigest = myself->indigest;
	to->inmaclength = myself->inmaclength;
	to->incompression = myself->incompression;

	// Allocate memory for key
	to->inkey = xrealloc(to->inkey, to->inkeylength);

	// Create a new key
	if(1 != RAND_bytes((unsigned char *)to->inkey, to->inkeylength)) {
		int err = ERR_get_error();
		logger(LOG_ERR, "Failed to generate random for key (%s)", ERR_error_string(err, NULL));
		return false; // Do not send insecure keys, let connection attempt fail.
	}

	if(to->incipher) {
		EVP_DecryptInit_ex(to->inctx, to->incipher, NULL, (unsigned char *)to->inkey, (unsigned char *)to->inkey + EVP_CIPHER_key_length(to->incipher));
	}

	// Reset sequence number and late packet window
	mykeyused = true;
	to->received_seqno = 0;

	if(replaywin) {
		memset(to->late, 0, replaywin);
	}

	// Convert to hexadecimal and send
	char key[2 * to->inkeylength + 1];
	bin2hex(to->inkey, key, to->inkeylength);
	key[to->inkeylength * 2] = '\0';

	return send_request(to->nexthop->connection, "%d %s %s %s %d %d %d %d", ANS_KEY,
	                    myself->name, to->name, key,
	                    to->incipher ? EVP_CIPHER_nid(to->incipher) : 0,
	                    to->indigest ? EVP_MD_type(to->indigest) : 0, to->inmaclength,
	                    to->incompression);
}

bool ans_key_h(connection_t *c) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char key[MAX_STRING_SIZE];
	char address[MAX_STRING_SIZE] = "";
	char port[MAX_STRING_SIZE] = "";
	int cipher, digest, maclength, compression;
	node_t *from, *to;

	if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" %d %d %d %d "MAX_STRING" "MAX_STRING,
	                from_name, to_name, key, &cipher, &digest, &maclength,
	                &compression, address, port) < 7) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ANS_KEY", c->name,
		       c->hostname);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "ANS_KEY", c->name, c->hostname, "invalid name");
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
		       "ANS_KEY", c->name, c->hostname, from_name);
		return true;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
		       "ANS_KEY", c->name, c->hostname, to_name);
		return true;
	}

	/* Forward it if necessary */

	if(to != myself) {
		if(tunnelserver) {
			return true;
		}

		if(!to->status.reachable) {
			logger(LOG_WARNING, "Got %s from %s (%s) destination %s which is not reachable",
			       "ANS_KEY", c->name, c->hostname, to_name);
			return true;
		}

		if(!*address && from->address.sa.sa_family != AF_UNSPEC && to->minmtu) {
			char *address, *port;
			ifdebug(PROTOCOL) logger(LOG_DEBUG, "Appending reflexive UDP address to ANS_KEY from %s to %s", from->name, to->name);
			sockaddr2str(&from->address, &address, &port);
			send_request(to->nexthop->connection, "%s %s %s", c->buffer, address, port);
			free(address);
			free(port);
			return true;
		}

		return send_request(to->nexthop->connection, "%s", c->buffer);
	}

	/* Don't use key material until every check has passed. */
	from->status.validkey = false;

	/* Update our copy of the origin's packet key */
	from->outkey = xrealloc(from->outkey, strlen(key) / 2);
	from->outkeylength = strlen(key) / 2;

	if(!hex2bin(key, from->outkey, from->outkeylength)) {
		logger(LOG_ERR, "Got bad %s from %s(%s): %s", "ANS_KEY", from->name, from->hostname, "invalid key");
		return true;
	}

	/* Check and lookup cipher and digest algorithms */

	if(cipher) {
		from->outcipher = EVP_get_cipherbynid(cipher);

		if(!from->outcipher) {
			logger(LOG_ERR, "Node %s (%s) uses unknown cipher!", from->name,
			       from->hostname);
			return true;
		}

		if(from->outkeylength != EVP_CIPHER_key_length(from->outcipher) + EVP_CIPHER_iv_length(from->outcipher)) {
			logger(LOG_ERR, "Node %s (%s) uses wrong keylength!", from->name,
			       from->hostname);
			return true;
		}
	} else {
		if(from->outkeylength != 1) {
			logger(LOG_ERR, "Node %s (%s) uses wrong keylength!", from->name, from->hostname);
			return true;
		}

		from->outcipher = NULL;
	}

	from->outmaclength = maclength;

	if(digest) {
		from->outdigest = EVP_get_digestbynid(digest);

		if(!from->outdigest) {
			logger(LOG_ERR, "Node %s (%s) uses unknown digest!", from->name,
			       from->hostname);
			return true;
		}

		if(from->outmaclength > EVP_MD_size(from->outdigest) || from->outmaclength < 0) {
			logger(LOG_ERR, "Node %s (%s) uses bogus MAC length!",
			       from->name, from->hostname);
			return true;
		}
	} else {
		from->outdigest = NULL;
	}

	if(compression < 0 || compression > 11) {
		logger(LOG_ERR, "Node %s (%s) uses bogus compression level!", from->name, from->hostname);
		return true;
	}

	from->outcompression = compression;

	if(from->outcipher)
		if(!EVP_EncryptInit_ex(from->outctx, from->outcipher, NULL, (unsigned char *)from->outkey, (unsigned char *)from->outkey + EVP_CIPHER_key_length(from->outcipher))) {
			logger(LOG_ERR, "Error during initialisation of key from %s (%s): %s",
			       from->name, from->hostname, ERR_error_string(ERR_get_error(), NULL));
			return true;
		}

	from->status.validkey = true;
	from->sent_seqno = 0;

	if(*address && *port) {
		ifdebug(PROTOCOL) logger(LOG_DEBUG, "Using reflexive UDP address from %s: %s port %s", from->name, address, port);
		sockaddr_t sa = str2sockaddr(address, port);
		update_node_udp(from, &sa);
	}

	if(from->options & OPTION_PMTU_DISCOVERY && !from->mtuevent) {
		send_mtu_probe(from);
	}

	return true;
}
