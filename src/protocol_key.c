/*
    protocol_key.c -- handle the meta-protocol, key exchange
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>

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

#include "cipher.h"
#include "connection.h"
#include "crypto.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "prf.h"
#include "protocol.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

static bool mykeyused = false;

void send_key_changed(void) {
#ifndef DISABLE_LEGACY
	send_request(everyone, "%d %x %s", KEY_CHANGED, rand(), myself->name);

	/* Immediately send new keys to directly connected nodes to keep UDP mappings alive */

	for list_each(connection_t, c, connection_list)
		if(c->edge && c->node && c->node->status.reachable && !c->node->status.sptps)
			send_ans_key(c->node);
#endif

	/* Force key exchange for connections using SPTPS */

	if(experimental) {
		for splay_each(node_t, n, node_tree)
			if(n->status.reachable && n->status.validkey && n->status.sptps)
				sptps_force_kex(&n->sptps);
	}
}

bool key_changed_h(connection_t *c, const char *request) {
	char name[MAX_STRING_SIZE];
	node_t *n;

	if(sscanf(request, "%*d %*x " MAX_STRING, name) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "KEY_CHANGED",
			   c->name, c->hostname);
		return false;
	}

	if(seen_request(request))
		return true;

	n = lookup_node(name);

	if(!n) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist",
			   "KEY_CHANGED", c->name, c->hostname, name);
		return true;
	}

	if(!n->status.sptps) {
		n->status.validkey = false;
		n->last_req_key = 0;
	}

	/* Tell the others */

	if(!tunnelserver)
		forward_request(c, request);

	return true;
}

static bool send_sptps_data_myself(void *handle, uint8_t type, const void *data, size_t len) {
	return send_sptps_data(handle, myself, type, data, len);
}

static bool send_initial_sptps_data(void *handle, uint8_t type, const void *data, size_t len) {
	node_t *to = handle;
	to->sptps.send_data = send_sptps_data_myself;
	char buf[len * 4 / 3 + 5];
	b64encode(data, buf, len);
	return send_request(to->nexthop->connection, "%d %s %s %d %s", REQ_KEY, myself->name, to->name, REQ_KEY, buf);
}

bool send_req_key(node_t *to) {
	if(to->status.sptps) {
		if(!node_read_ecdsa_public_key(to)) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "No Ed25519 key known for %s (%s)", to->name, to->hostname);
			send_request(to->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, to->name, REQ_PUBKEY);
			return true;
		}

		char label[25 + strlen(myself->name) + strlen(to->name)];
		snprintf(label, sizeof label, "tinc UDP key expansion %s %s", myself->name, to->name);
		sptps_stop(&to->sptps);
		to->status.validkey = false;
		to->status.waitingforkey = true;
		to->last_req_key = now.tv_sec;
		to->incompression = myself->incompression;
		return sptps_start(&to->sptps, to, true, true, myself->connection->ecdsa, to->ecdsa, label, sizeof label, send_initial_sptps_data, receive_sptps_record);
	}

	return send_request(to->nexthop->connection, "%d %s %s", REQ_KEY, myself->name, to->name);
}

/* REQ_KEY is overloaded to allow arbitrary requests to be routed between two nodes. */

static bool req_key_ext_h(connection_t *c, const char *request, node_t *from, node_t *to, int reqno) {
	/* If this is a SPTPS packet, see if sending UDP info helps.
	   Note that we only do this if we're the destination or the static relay;
	   otherwise every hop would initiate its own UDP info message, resulting in elevated chatter. */
	if((reqno == REQ_KEY || reqno == SPTPS_PACKET) && to->via == myself)
		send_udp_info(myself, from);

	if(reqno == SPTPS_PACKET) {
		/* This is a SPTPS data packet. */

		char buf[MAX_STRING_SIZE];
		int len;
		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, buf) != 1 || !(len = b64decode(buf, buf, strlen(buf)))) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s) to %s (%s): %s", "SPTPS_PACKET", from->name, from->hostname, to->name, to->hostname, "invalid SPTPS data");
			return true;
		}

		if(to != myself) {
			/* We don't just forward the request, because we want to use UDP if it's available. */
			send_sptps_data(to, from, 0, buf, len);
			try_tx(to, true);
		} else {
			/* The packet is for us */
			if(!sptps_receive_data(&from->sptps, buf, len)) {
				/* Uh-oh. It might be that the tunnel is stuck in some corrupted state,
				   so let's restart SPTPS in case that helps. But don't do that too often
				   to prevent storms. */
				if(from->last_req_key < now.tv_sec - 10) {
					logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to decode TCP packet from %s (%s), restarting SPTPS", from->name, from->hostname);
					send_req_key(from);
				}
				return true;
			}
			send_mtu_info(myself, from, MTU);
		}

		return true;
	}

	/* Requests that are not SPTPS data packets are forwarded as-is. */

	if (to != myself)
		return send_request(to->nexthop->connection, "%s", request);

	/* The request is for us */

	switch(reqno) {
		case REQ_PUBKEY: {
			if(!node_read_ecdsa_public_key(from)) {
				/* Request their key *before* we send our key back. Otherwise the first SPTPS packet from them will get dropped. */
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Preemptively requesting Ed25519 key for %s (%s)", from->name, from->hostname);
				send_request(from->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, from->name, REQ_PUBKEY);
			}
			char *pubkey = ecdsa_get_base64_public_key(myself->connection->ecdsa);
			send_request(from->nexthop->connection, "%d %s %s %d %s", REQ_KEY, myself->name, from->name, ANS_PUBKEY, pubkey);
			free(pubkey);
			return true;
		}

		case ANS_PUBKEY: {
			if(node_read_ecdsa_public_key(from)) {
				logger(DEBUG_PROTOCOL, LOG_WARNING, "Got ANS_PUBKEY from %s (%s) even though we already have his pubkey", from->name, from->hostname);
				return true;
			}

			char pubkey[MAX_STRING_SIZE];
			if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, pubkey) != 1 || !(from->ecdsa = ecdsa_set_base64_public_key(pubkey))) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ANS_PUBKEY", from->name, from->hostname, "invalid pubkey");
				return true;
			}

			logger(DEBUG_PROTOCOL, LOG_INFO, "Learned Ed25519 public key from %s (%s)", from->name, from->hostname);
			append_config_file(from->name, "Ed25519PublicKey", pubkey);
			return true;
		}

		case REQ_KEY: {
			if(!node_read_ecdsa_public_key(from)) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "No Ed25519 key known for %s (%s)", from->name, from->hostname);
				send_request(from->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, from->name, REQ_PUBKEY);
				return true;
			}

			if(from->sptps.label)
				logger(DEBUG_ALWAYS, LOG_DEBUG, "Got REQ_KEY from %s while we already started a SPTPS session!", from->name);

			char buf[MAX_STRING_SIZE];
			int len;

			if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, buf) != 1 || !(len = b64decode(buf, buf, strlen(buf)))) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "REQ_SPTPS_START", from->name, from->hostname, "invalid SPTPS data");
				return true;
			}

			char label[25 + strlen(from->name) + strlen(myself->name)];
			snprintf(label, sizeof label, "tinc UDP key expansion %s %s", from->name, myself->name);
			sptps_stop(&from->sptps);
			from->status.validkey = false;
			from->status.waitingforkey = true;
			from->last_req_key = now.tv_sec;
			sptps_start(&from->sptps, from, false, true, myself->connection->ecdsa, from->ecdsa, label, sizeof label, send_sptps_data_myself, receive_sptps_record);
			sptps_receive_data(&from->sptps, buf, len);
			send_mtu_info(myself, from, MTU);
			return true;
		}

		default:
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown extended REQ_KEY request from %s (%s): %s", from->name, from->hostname, request);
			return true;
	}
}

bool req_key_h(connection_t *c, const char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;
	int reqno = 0;

	if(sscanf(request, "%*d " MAX_STRING " " MAX_STRING " %d", from_name, to_name, &reqno) < 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "REQ_KEY", c->name,
			   c->hostname);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "REQ_KEY", c->name, c->hostname, "invalid name");
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
			   "REQ_KEY", c->name, c->hostname, from_name);
		return true;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
			   "REQ_KEY", c->name, c->hostname, to_name);
		return true;
	}

	/* Check if this key request is for us */

	if(to == myself) {                      /* Yes */
		/* Is this an extended REQ_KEY message? */
		if(experimental && reqno)
			return req_key_ext_h(c, request, from, to, reqno);

		/* No, just send our key back */
		send_ans_key(from);
	} else {
		if(tunnelserver)
			return true;

		if(!to->status.reachable) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Got %s from %s (%s) destination %s which is not reachable",
				"REQ_KEY", c->name, c->hostname, to_name);
			return true;
		}

		/* Is this an extended REQ_KEY message? */
		if(experimental && reqno)
			return req_key_ext_h(c, request, from, to, reqno);

		send_request(to->nexthop->connection, "%s", request);
	}

	return true;
}

bool send_ans_key(node_t *to) {
	if(to->status.sptps)
		abort();

#ifdef DISABLE_LEGACY
	return false;
#else
	size_t keylen = myself->incipher ? cipher_keylength(myself->incipher) : 1;
	char key[keylen * 2 + 1];

	randomize(key, keylen);

	cipher_close(to->incipher);
	digest_close(to->indigest);

	if(myself->incipher) {
		to->incipher = cipher_open_by_nid(cipher_get_nid(myself->incipher));
		if(!to->incipher)
			abort();
		if(!cipher_set_key(to->incipher, key, false))
			abort();
	}

	if(myself->indigest) {
		to->indigest = digest_open_by_nid(digest_get_nid(myself->indigest), digest_length(myself->indigest));
		if(!to->indigest)
			abort();
		if(!digest_set_key(to->indigest, key, keylen))
			abort();
	}

	to->incompression = myself->incompression;

	bin2hex(key, key, keylen);

	// Reset sequence number and late packet window
	mykeyused = true;
	to->received_seqno = 0;
	to->received = 0;
	if(replaywin) memset(to->late, 0, replaywin);

	to->status.validkey_in = true;

	return send_request(to->nexthop->connection, "%d %s %s %s %d %d %d %d", ANS_KEY,
						myself->name, to->name, key,
						cipher_get_nid(to->incipher),
						digest_get_nid(to->indigest),
						(int)digest_length(to->indigest),
						to->incompression);
#endif
}

bool ans_key_h(connection_t *c, const char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char key[MAX_STRING_SIZE];
	char address[MAX_STRING_SIZE] = "";
	char port[MAX_STRING_SIZE] = "";
	int cipher, digest, maclength, compression, keylen;
	node_t *from, *to;

	if(sscanf(request, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" %d %d %d %d "MAX_STRING" "MAX_STRING,
		from_name, to_name, key, &cipher, &digest, &maclength,
		&compression, address, port) < 7) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ANS_KEY", c->name,
			   c->hostname);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ANS_KEY", c->name, c->hostname, "invalid name");
		return false;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
			   "ANS_KEY", c->name, c->hostname, from_name);
		return true;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
			   "ANS_KEY", c->name, c->hostname, to_name);
		return true;
	}

	/* Forward it if necessary */

	if(to != myself) {
		if(tunnelserver)
			return true;

		if(!to->status.reachable) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Got %s from %s (%s) destination %s which is not reachable",
				   "ANS_KEY", c->name, c->hostname, to_name);
			return true;
		}

		if(!*address && from->address.sa.sa_family != AF_UNSPEC && to->minmtu) {
			char *address, *port;
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Appending reflexive UDP address to ANS_KEY from %s to %s", from->name, to->name);
			sockaddr2str(&from->address, &address, &port);
			send_request(to->nexthop->connection, "%s %s %s", request, address, port);
			free(address);
			free(port);
			return true;
		}

		return send_request(to->nexthop->connection, "%s", request);
	}

#ifndef DISABLE_LEGACY
	/* Don't use key material until every check has passed. */
	cipher_close(from->outcipher);
	digest_close(from->outdigest);
#endif
	if (!from->status.sptps) from->status.validkey = false;

	if(compression < 0 || compression > 11) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses bogus compression level!", from->name, from->hostname);
		return true;
	}

	from->outcompression = compression;

	/* SPTPS or old-style key exchange? */

	if(from->status.sptps) {
		char buf[strlen(key)];
		int len = b64decode(key, buf, strlen(key));
		if(!len || !sptps_receive_data(&from->sptps, buf, len)) {
			/* Uh-oh. It might be that the tunnel is stuck in some corrupted state,
			   so let's restart SPTPS in case that helps. But don't do that too often
			   to prevent storms.
			   Note that simply relying on handshake timeout is not enough, because
			   that doesn't apply to key regeneration. */
			if(from->last_req_key < now.tv_sec - 10) {
				logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to decode handshake TCP packet from %s (%s), restarting SPTPS", from->name, from->hostname);
				send_req_key(from);
			}
			return true;
		}

		if(from->status.validkey) {
			if(*address && *port) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Using reflexive UDP address from %s: %s port %s", from->name, address, port);
				sockaddr_t sa = str2sockaddr(address, port);
				update_node_udp(from, &sa);
			}
		}

		send_mtu_info(myself, from, MTU);

		return true;
	}

#ifdef DISABLE_LEGACY
	logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses legacy protocol!", from->name, from->hostname);
	return false;
#else
	/* Check and lookup cipher and digest algorithms */

	if(cipher) {
		if(!(from->outcipher = cipher_open_by_nid(cipher))) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses unknown cipher!", from->name, from->hostname);
			return false;
		}
	} else {
		from->outcipher = NULL;
	}

	if(digest) {
		if(!(from->outdigest = digest_open_by_nid(digest, maclength))) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses unknown digest!", from->name, from->hostname);
			return false;
		}
	} else {
		from->outdigest = NULL;
	}

	if(maclength != digest_length(from->outdigest)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses bogus MAC length!", from->name, from->hostname);
		return false;
	}

	/* Process key */

	keylen = hex2bin(key, key, sizeof key);

	if(keylen != (from->outcipher ? cipher_keylength(from->outcipher) : 1)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses wrong keylength!", from->name, from->hostname);
		return true;
	}

	/* Update our copy of the origin's packet key */

	if(from->outcipher && !cipher_set_key(from->outcipher, key, true))
		return false;
	if(from->outdigest && !digest_set_key(from->outdigest, key, keylen))
		return false;

	from->status.validkey = true;
	from->sent_seqno = 0;

	if(*address && *port) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Using reflexive UDP address from %s: %s port %s", from->name, address, port);
		sockaddr_t sa = str2sockaddr(address, port);
		update_node_udp(from, &sa);
	}

	return true;
#endif
}
