/*
    protocol_auth.c -- handle the meta-protocol, authentication
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2010 Guus Sliepen <guus@tinc-vpn.org>

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
#include "conf.h"
#include "connection.h"
#include "control.h"
#include "control_common.h"
#include "cipher.h"
#include "crypto.h"
#include "digest.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "prf.h"
#include "protocol.h"
#include "rsa.h"
#include "utils.h"
#include "xalloc.h"

bool send_id(connection_t *c) {
	gettimeofday(&c->start, NULL);

	int minor = 0;

	if(experimental) {
		if(c->config_tree && !read_ecdsa_public_key(c))
			minor = 1;
		else
			minor = myself->connection->protocol_minor;
	}

	return send_request(c, "%d %s %d.%d", ID, myself->connection->name, myself->connection->protocol_major, minor);
}

bool id_h(connection_t *c, char *request) {
	char name[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING " %d.%d", name, &c->protocol_major, &c->protocol_minor) < 2) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ID", c->name,
			   c->hostname);
		return false;
	}

	/* Check if this is a control connection */

	if(name[0] == '^' && !strcmp(name + 1, controlcookie)) {
		c->status.control = true;
		c->allow_request = CONTROL;
		c->last_ping_time = time(NULL) + 3600;
		return send_request(c, "%d %d %d", ACK, TINC_CTL_VERSION_CURRENT, getpid());
	}

	/* Check if identity is a valid name */

	if(!check_id(name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "ID", c->name,
			   c->hostname, "invalid name");
		return false;
	}

	/* If this is an outgoing connection, make sure we are connected to the right host */

	if(c->outgoing) {
		if(strcmp(c->name, name)) {
			logger(LOG_ERR, "Peer %s is %s instead of %s", c->hostname, name,
				   c->name);
			return false;
		}
	} else {
		if(c->name)
			free(c->name);
		c->name = xstrdup(name);
	}

	/* Check if version matches */

	if(c->protocol_major != myself->connection->protocol_major) {
		logger(LOG_ERR, "Peer %s (%s) uses incompatible version %d.%d",
			   c->name, c->hostname, c->protocol_major, c->protocol_minor);
		return false;
	}

	if(bypass_security) {
		if(!c->config_tree)
			init_configuration(&c->config_tree);
		c->allow_request = ACK;
		return send_ack(c);
	}

	if(!c->config_tree) {
		init_configuration(&c->config_tree);

		if(!read_connection_config(c)) {
			logger(LOG_ERR, "Peer %s had unknown identity (%s)", c->hostname,
				   c->name);
			return false;
		}

		if(experimental && c->protocol_minor >= 2)
			if(!read_ecdsa_public_key(c))
				return false;
	} else {
		if(!ecdsa_active(&c->ecdsa))
			c->protocol_minor = 1;
	}

	if(!experimental)
		c->protocol_minor = 0;

	c->allow_request = METAKEY;

	if(c->protocol_minor >= 2)
		return send_metakey_ec(c);
	else
		return send_metakey(c);
}

bool send_metakey_ec(connection_t *c) {
	logger(LOG_DEBUG, "Sending ECDH metakey to %s", c->name);

	size_t siglen = ecdsa_size(&myself->connection->ecdsa);

	char key[(ECDH_SIZE + siglen) * 2 + 1];

	// TODO: include nonce? Use relevant parts of SSH or TLS protocol

	if(!ecdh_generate_public(&c->ecdh, key))
		return false;

	if(!ecdsa_sign(&myself->connection->ecdsa, key, ECDH_SIZE, key + ECDH_SIZE))
		return false;

	b64encode(key, key, ECDH_SIZE + siglen);
	
	return send_request(c, "%d %s", METAKEY, key);
}

bool send_metakey(connection_t *c) {
	if(!read_rsa_public_key(c))
		return false;

	if(!cipher_open_blowfish_ofb(&c->outcipher))
		return false;
	
	if(!digest_open_sha1(&c->outdigest, -1))
		return false;

	size_t len = rsa_size(&c->rsa);
	char key[len];
	char enckey[len];
	char hexkey[2 * len + 1];

	/* Create a random key */

	randomize(key, len);

	/* The message we send must be smaller than the modulus of the RSA key.
	   By definition, for a key of k bits, the following formula holds:

	   2^(k-1) <= modulus < 2^(k)

	   Where ^ means "to the power of", not "xor".
	   This means that to be sure, we must choose our message < 2^(k-1).
	   This can be done by setting the most significant bit to zero.
	 */

	key[0] &= 0x7F;

	cipher_set_key_from_rsa(&c->outcipher, key, len, true);

	ifdebug(SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(LOG_DEBUG, "Generated random meta key (unencrypted): %s", hexkey);
	}

	/* Encrypt the random data

	   We do not use one of the PKCS padding schemes here.
	   This is allowed, because we encrypt a totally random string
	   with a length equal to that of the modulus of the RSA key.
	 */

	if(!rsa_public_encrypt(&c->rsa, key, len, enckey)) {
		logger(LOG_ERR, "Error during encryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	/* Convert the encrypted random data to a hexadecimal formatted string */

	bin2hex(enckey, hexkey, len);

	/* Send the meta key */

	bool result = send_request(c, "%d %d %d %d %d %s", METAKEY,
			 cipher_get_nid(&c->outcipher),
			 digest_get_nid(&c->outdigest), c->outmaclength,
			 c->outcompression, hexkey);
	
	c->status.encryptout = true;
	return result;
}

static bool metakey_ec_h(connection_t *c, const char *request) {
	size_t siglen = ecdsa_size(&c->ecdsa);
	char key[MAX_STRING_SIZE];
	char sig[siglen];

	logger(LOG_DEBUG, "Got ECDH metakey from %s", c->name);

	if(sscanf(request, "%*d " MAX_STRING, key) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "METAKEY", c->name, c->hostname);
		return false;
	}

	int inlen = b64decode(key, key, sizeof key);

	if(inlen != (ECDH_SIZE + siglen)) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong keylength");
		return false;
	}

	if(!ecdsa_verify(&c->ecdsa, key, ECDH_SIZE, key + ECDH_SIZE)) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "invalid ECDSA signature");
		return false;
	}

	char shared[ECDH_SHARED_SIZE];

	if(!ecdh_compute_shared(&c->ecdh, key, shared))
		return false;

	/* Update our crypto end */

	if(!cipher_open_by_name(&c->incipher, "aes-256-ofb"))
		return false;
	if(!digest_open_by_name(&c->indigest, "sha512", -1))
		return false;
	if(!cipher_open_by_name(&c->outcipher, "aes-256-ofb"))
		return false;
	if(!digest_open_by_name(&c->outdigest, "sha512", -1))
		return false;

	size_t mykeylen = cipher_keylength(&c->incipher);
	size_t hiskeylen = cipher_keylength(&c->outcipher);

	char *mykey;
	char *hiskey;
	char *seed;
	
	if(strcmp(myself->name, c->name) < 0) {
		mykey = key;
		hiskey = key + mykeylen * 2;
		xasprintf(&seed, "tinc TCP key expansion %s %s", myself->name, c->name);
	} else {
		mykey = key + hiskeylen * 2;
		hiskey = key;
		xasprintf(&seed, "tinc TCP key expansion %s %s", c->name, myself->name);
	}

	if(!prf(shared, ECDH_SHARED_SIZE, seed, strlen(seed), key, hiskeylen * 2 + mykeylen * 2))
		return false;

	free(seed);

	cipher_set_key(&c->incipher, mykey, false);
	digest_set_key(&c->indigest, mykey + mykeylen, mykeylen);

	cipher_set_key(&c->outcipher, hiskey, true);
	digest_set_key(&c->outdigest, hiskey + hiskeylen, hiskeylen);

	c->status.decryptin = true;
	c->status.encryptout = true;
	c->allow_request = CHALLENGE;

	return send_challenge(c);
}

bool metakey_h(connection_t *c, char *request) {
	if(c->protocol_minor >= 2)
		return metakey_ec_h(c, request);

	char hexkey[MAX_STRING_SIZE];
	int cipher, digest, maclength, compression;
	size_t len = rsa_size(&myself->connection->rsa);
	char enckey[len];
	char key[len];

	if(sscanf(request, "%*d %d %d %d %d " MAX_STRING, &cipher, &digest, &maclength, &compression, hexkey) != 5) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "METAKEY", c->name, c->hostname);
		return false;
	}

	/* Convert the challenge from hexadecimal back to binary */

	int inlen = hex2bin(hexkey, enckey, sizeof enckey);

	/* Check if the length of the meta key is all right */

	if(inlen != len) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong keylength");
		return false;
	}

	/* Decrypt the meta key */

	if(!rsa_private_decrypt(&myself->connection->rsa, enckey, len, key)) {
		logger(LOG_ERR, "Error during decryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	ifdebug(SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(LOG_DEBUG, "Received random meta key (unencrypted): %s", hexkey);
	}

	/* Check and lookup cipher and digest algorithms */

	if(!cipher_open_by_nid(&c->incipher, cipher) || !cipher_set_key_from_rsa(&c->incipher, key, len, false)) {
		logger(LOG_ERR, "Error during initialisation of cipher from %s (%s)", c->name, c->hostname);
		return false;
	}

	if(!digest_open_by_nid(&c->indigest, digest, -1)) {
		logger(LOG_ERR, "Error during initialisation of digest from %s (%s)", c->name, c->hostname);
		return false;
	}

	c->status.decryptin = true;

	c->allow_request = CHALLENGE;

	return send_challenge(c);
}

bool send_challenge(connection_t *c) {
	size_t len = c->protocol_minor >= 2 ? ECDH_SIZE : rsa_size(&c->rsa);
	char buffer[len * 2 + 1];

	if(!c->hischallenge)
		c->hischallenge = xrealloc(c->hischallenge, len);

	/* Copy random data to the buffer */

	randomize(c->hischallenge, len);

	/* Convert to hex */

	bin2hex(c->hischallenge, buffer, len);

	/* Send the challenge */

	return send_request(c, "%d %s", CHALLENGE, buffer);
}

bool challenge_h(connection_t *c, char *request) {
	char buffer[MAX_STRING_SIZE];
	size_t len = c->protocol_minor >= 2 ? ECDH_SIZE : rsa_size(&myself->connection->rsa);
	size_t digestlen = digest_length(&c->indigest);
	char digest[digestlen];

	if(sscanf(request, "%*d " MAX_STRING, buffer) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "CHALLENGE", c->name, c->hostname);
		return false;
	}

	/* Convert the challenge from hexadecimal back to binary */

	int inlen = hex2bin(buffer, buffer, sizeof buffer);

	/* Check if the length of the challenge is all right */

	if(inlen != len) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge length");
		return false;
	}

	c->allow_request = CHAL_REPLY;

	/* Calculate the hash from the challenge we received */

	digest_create(&c->indigest, buffer, len, digest);

	/* Convert the hash to a hexadecimal formatted string */

	bin2hex(digest, buffer, digestlen);

	/* Send the reply */

	return send_request(c, "%d %s", CHAL_REPLY, buffer);
}

bool chal_reply_h(connection_t *c, char *request) {
	char hishash[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, hishash) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "CHAL_REPLY", c->name,
			   c->hostname);
		return false;
	}

	/* Convert the hash to binary format */

	int inlen = hex2bin(hishash, hishash, sizeof hishash);

	/* Check if the length of the hash is all right */

	if(inlen != digest_length(&c->outdigest)) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply length");
		return false;
	}


	/* Verify the hash */

	if(!digest_verify(&c->outdigest, c->hischallenge, c->protocol_minor >= 2 ? ECDH_SIZE : rsa_size(&c->rsa), hishash)) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply");
		return false;
	}

	/* Identity has now been positively verified.
	   Send an acknowledgement with the rest of the information needed.
	 */

	free(c->hischallenge);
	c->hischallenge = NULL;
	c->allow_request = ACK;

	return send_ack(c);
}

static bool send_upgrade(connection_t *c) {
	/* Special case when protocol_minor is 1: the other end is ECDSA capable,
	 * but doesn't know our key yet. So send it now. */

	char *pubkey = ecdsa_get_base64_public_key(&myself->connection->ecdsa);

	if(!pubkey)
		return false;

	bool result = send_request(c, "%d %s", ACK, pubkey);
	free(pubkey);
	return result;
}

bool send_ack(connection_t *c) {
	if(c->protocol_minor == 1)
		return send_upgrade(c);

	/* ACK message contains rest of the information the other end needs
	   to create node_t and edge_t structures. */

	struct timeval now;
	bool choice;

	/* Estimate weight */

	gettimeofday(&now, NULL);
	c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;

	/* Check some options */

	if((get_config_bool(lookup_config(c->config_tree, "IndirectData"), &choice) && choice) || myself->options & OPTION_INDIRECT)
		c->options |= OPTION_INDIRECT;

	if((get_config_bool(lookup_config(c->config_tree, "TCPOnly"), &choice) && choice) || myself->options & OPTION_TCPONLY)
		c->options |= OPTION_TCPONLY | OPTION_INDIRECT;

	if(myself->options & OPTION_PMTU_DISCOVERY)
		c->options |= OPTION_PMTU_DISCOVERY;

	choice = myself->options & OPTION_CLAMP_MSS;
	get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice);
	if(choice)
		c->options |= OPTION_CLAMP_MSS;

	get_config_int(lookup_config(c->config_tree, "Weight"), &c->estimated_weight);

	return send_request(c, "%d %s %d %x", ACK, myport, c->estimated_weight, c->options);
}

static void send_everything(connection_t *c) {
	splay_node_t *node, *node2;
	node_t *n;
	subnet_t *s;
	edge_t *e;

	/* Send all known subnets and edges */

	if(tunnelserver) {
		for(node = myself->subnet_tree->head; node; node = node->next) {
			s = node->data;
			send_add_subnet(c, s);
		}

		return;
	}

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;

		for(node2 = n->subnet_tree->head; node2; node2 = node2->next) {
			s = node2->data;
			send_add_subnet(c, s);
		}

		for(node2 = n->edge_tree->head; node2; node2 = node2->next) {
			e = node2->data;
			send_add_edge(c, e);
		}
	}
}

static bool upgrade_h(connection_t *c, char *request) {
	char pubkey[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, pubkey) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name, c->hostname);
		return false;
	}

	if(ecdsa_active(&c->ecdsa) || read_ecdsa_public_key(c)) {
		logger(LOG_INFO, "Already have ECDSA public key from %s (%s), not upgrading.", c->name, c->hostname);
		return false;
	}

	logger(LOG_INFO, "Got ECDSA public key from %s (%s), upgrading!", c->name, c->hostname);
	append_config_file(c->name, "ECDSAPublicKey", pubkey);
	c->allow_request = TERMREQ;
	return send_termreq(c);
}

bool ack_h(connection_t *c, char *request) {
	if(c->protocol_minor == 1)
		return upgrade_h(c, request);

	char hisport[MAX_STRING_SIZE];
	char *hisaddress;
	int weight, mtu;
	uint32_t options;
	node_t *n;
	bool choice;

	if(sscanf(request, "%*d " MAX_STRING " %d %x", hisport, &weight, &options) != 3) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name,
			   c->hostname);
		return false;
	}

	/* Check if we already have a node_t for him */

	n = lookup_node(c->name);

	if(!n) {
		n = new_node();
		n->name = xstrdup(c->name);
		node_add(n);
	} else {
		if(n->connection) {
			/* Oh dear, we already have a connection to this node. */
			ifdebug(CONNECTIONS) logger(LOG_DEBUG, "Established a second connection with %s (%s), closing old connection", n->connection->name, n->connection->hostname);

			if(n->connection->outgoing) {
				if(c->outgoing)
					logger(LOG_WARNING, "Two outgoing connections to the same node!");
				else
					c->outgoing = n->connection->outgoing;

				n->connection->outgoing = NULL;
			}

			terminate_connection(n->connection, false);
			/* Run graph algorithm to purge key and make sure up/down scripts are rerun with new IP addresses and stuff */
			graph();
		}
	}

	n->connection = c;
	c->node = n;
	if(!(c->options & options & OPTION_PMTU_DISCOVERY)) {
		c->options &= ~OPTION_PMTU_DISCOVERY;
		options &= ~OPTION_PMTU_DISCOVERY;
	}
	c->options |= options;

	if(get_config_int(lookup_config(c->config_tree, "PMTU"), &mtu) && mtu < n->mtu)
		n->mtu = mtu;

	if(get_config_int(lookup_config(config_tree, "PMTU"), &mtu) && mtu < n->mtu)
		n->mtu = mtu;

	if(get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice)) {
		if(choice)
			c->options |= OPTION_CLAMP_MSS;
		else
			c->options &= ~OPTION_CLAMP_MSS;
	}

	if(c->protocol_minor > 0)
		c->node->status.ecdh = true;

	/* Activate this connection */

	c->allow_request = ALL;
	c->status.active = true;

	ifdebug(CONNECTIONS) logger(LOG_NOTICE, "Connection with %s (%s) activated", c->name,
			   c->hostname);

	/* Send him everything we know */

	send_everything(c);

	/* Create an edge_t for this connection */

	c->edge = new_edge();
	c->edge->from = myself;
	c->edge->to = n;
	sockaddr2str(&c->address, &hisaddress, NULL);
	c->edge->address = str2sockaddr(hisaddress, hisport);
	free(hisaddress);
	c->edge->weight = (weight + c->estimated_weight) / 2;
	c->edge->connection = c;
	c->edge->options = c->options;

	edge_add(c->edge);

	/* Notify everyone of the new edge */

	if(tunnelserver)
		send_add_edge(c, c->edge);
	else
		send_add_edge(broadcast, c->edge);

	/* Run MST and SSSP algorithms */

	graph();

	return true;
}
