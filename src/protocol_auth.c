/*
    protocol_auth.c -- handle the meta-protocol, authentication
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

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "proxy.h"
#include "utils.h"
#include "xalloc.h"

bool send_id(connection_t *c) {
	if(proxytype && c->outgoing && !c->status.proxy_passed) {
		return send_proxyrequest(c);
	}

	return send_request(c, "%d %s %d", ID, myself->connection->name,
	                    myself->connection->protocol_version);
}

bool id_h(connection_t *c) {
	char name[MAX_STRING_SIZE];

	if(sscanf(c->buffer, "%*d " MAX_STRING " %d", name, &c->protocol_version) != 2) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ID", c->name,
		       c->hostname);
		return false;
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
		if(c->name) {
			free(c->name);
		}

		c->name = xstrdup(name);
	}

	/* Check if version matches */

	if(c->protocol_version != myself->connection->protocol_version) {
		logger(LOG_ERR, "Peer %s (%s) uses incompatible version %d",
		       c->name, c->hostname, c->protocol_version);
		return false;
	}

	if(bypass_security) {
		if(!c->config_tree) {
			init_configuration(&c->config_tree);
		}

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
	}

	if(!read_rsa_public_key(c)) {
		return false;
	}

	c->allow_request = METAKEY;

	return send_metakey(c);
}

static uint64_t byte_budget(const EVP_CIPHER *cipher) {
	/* Hopefully some failsafe way to calculate the maximum amount of bytes to
	   send/receive with a given cipher before we might run into birthday paradox
	   attacks. Because we might use different modes, the block size of the mode
	   might be 1 byte. In that case, use the IV length. Ensure the whole thing
	   is limited to what can be represented with a 64 bits integer.
	 */

	int ivlen = EVP_CIPHER_iv_length(cipher);
	int blklen = EVP_CIPHER_block_size(cipher);
	int len = blklen > 1 ? blklen : ivlen > 1 ? ivlen : 8;
	int bits = len * 4 - 1;
	return bits < 64 ? UINT64_C(1) << bits : UINT64_MAX;
}

bool send_metakey(connection_t *c) {
	bool x;

	int len = RSA_size(c->rsa_key);

	/* Allocate buffers for the meta key */

	char buffer[2 * len + 1];

	c->outkey = xrealloc(c->outkey, len);

	if(!c->outctx) {
		c->outctx = EVP_CIPHER_CTX_new();

		if(!c->outctx) {
			abort();
		}
	}

	/* Copy random data to the buffer */

	if(1 != RAND_bytes((unsigned char *)c->outkey, len)) {
		int err = ERR_get_error();
		logger(LOG_ERR, "Failed to generate meta key (%s)", ERR_error_string(err, NULL));
		return false;
	}


	/* The message we send must be smaller than the modulus of the RSA key.
	   By definition, for a key of k bits, the following formula holds:

	   2^(k-1) <= modulus < 2^(k)

	   Where ^ means "to the power of", not "xor".
	   This means that to be sure, we must choose our message < 2^(k-1).
	   This can be done by setting the most significant bit to zero.
	 */

	c->outkey[0] &= 0x7F;

	ifdebug(SCARY_THINGS) {
		bin2hex(c->outkey, buffer, len);
		buffer[len * 2] = '\0';
		logger(LOG_DEBUG, "Generated random meta key (unencrypted): %s",
		       buffer);
	}

	/* Encrypt the random data

	   We do not use one of the PKCS padding schemes here.
	   This is allowed, because we encrypt a totally random string
	   with a length equal to that of the modulus of the RSA key.
	 */

	if(RSA_public_encrypt(len, (unsigned char *)c->outkey, (unsigned char *)buffer, c->rsa_key, RSA_NO_PADDING) != len) {
		logger(LOG_ERR, "Error during encryption of meta key for %s (%s): %s",
		       c->name, c->hostname, ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	/* Convert the encrypted random data to a hexadecimal formatted string */

	bin2hex(buffer, buffer, len);
	buffer[len * 2] = '\0';

	/* Send the meta key */

	x = send_request(c, "%d %d %d %d %d %s", METAKEY,
	                 c->outcipher ? EVP_CIPHER_nid(c->outcipher) : 0,
	                 c->outdigest ? EVP_MD_type(c->outdigest) : 0, c->outmaclength,
	                 c->outcompression, buffer);

	/* Further outgoing requests are encrypted with the key we just generated */

	if(c->outcipher) {
		if(!EVP_EncryptInit(c->outctx, c->outcipher,
		                    (unsigned char *)c->outkey + len - EVP_CIPHER_key_length(c->outcipher),
		                    (unsigned char *)c->outkey + len - EVP_CIPHER_key_length(c->outcipher) -
		                    EVP_CIPHER_iv_length(c->outcipher))) {
			logger(LOG_ERR, "Error during initialisation of cipher for %s (%s): %s",
			       c->name, c->hostname, ERR_error_string(ERR_get_error(), NULL));
			return false;
		}

		c->outbudget = byte_budget(c->outcipher);
		c->status.encryptout = true;
	}

	return x;
}

bool metakey_h(connection_t *c) {
	char buffer[MAX_STRING_SIZE];
	int cipher, digest, maclength, compression;
	int len;

	if(sscanf(c->buffer, "%*d %d %d %d %d " MAX_STRING, &cipher, &digest, &maclength, &compression, buffer) != 5) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "METAKEY", c->name,
		       c->hostname);
		return false;
	}

	len = RSA_size(myself->connection->rsa_key);

	/* Check if the length of the meta key is all right */

	if(strlen(buffer) != (size_t)len * 2) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong keylength");
		return false;
	}

	/* Allocate buffers for the meta key */

	c->inkey = xrealloc(c->inkey, len);

	if(!c->inctx) {
		c->inctx = EVP_CIPHER_CTX_new();

		if(!c->inctx) {
			abort();
		}
	}

	/* Convert the challenge from hexadecimal back to binary */

	if(!hex2bin(buffer, buffer, len)) {
		logger(LOG_ERR, "Got bad %s from %s(%s): %s", "METAKEY", c->name, c->hostname, "invalid key");
		return false;
	}

	/* Decrypt the meta key */

	if(RSA_private_decrypt(len, (unsigned char *)buffer, (unsigned char *)c->inkey, myself->connection->rsa_key, RSA_NO_PADDING) != len) {  /* See challenge() */
		logger(LOG_ERR, "Error during decryption of meta key for %s (%s): %s",
		       c->name, c->hostname, ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	ifdebug(SCARY_THINGS) {
		bin2hex(c->inkey, buffer, len);
		buffer[len * 2] = '\0';
		logger(LOG_DEBUG, "Received random meta key (unencrypted): %s", buffer);
	}

	/* All incoming requests will now be encrypted. */

	/* Check and lookup cipher and digest algorithms */

	if(cipher) {
		c->incipher = EVP_get_cipherbynid(cipher);

		if(!c->incipher) {
			logger(LOG_ERR, "%s (%s) uses unknown cipher!", c->name, c->hostname);
			return false;
		}

		if(!EVP_DecryptInit(c->inctx, c->incipher,
		                    (unsigned char *)c->inkey + len - EVP_CIPHER_key_length(c->incipher),
		                    (unsigned char *)c->inkey + len - EVP_CIPHER_key_length(c->incipher) -
		                    EVP_CIPHER_iv_length(c->incipher))) {
			logger(LOG_ERR, "Error during initialisation of cipher from %s (%s): %s",
			       c->name, c->hostname, ERR_error_string(ERR_get_error(), NULL));
			return false;
		}

		c->inbudget = byte_budget(c->incipher);
		c->status.decryptin = true;
	} else {
		c->incipher = NULL;
	}

	c->inmaclength = maclength;

	if(digest) {
		c->indigest = EVP_get_digestbynid(digest);

		if(!c->indigest) {
			logger(LOG_ERR, "Node %s (%s) uses unknown digest!", c->name, c->hostname);
			return false;
		}

		if(c->inmaclength > EVP_MD_size(c->indigest) || c->inmaclength < 0) {
			logger(LOG_ERR, "%s (%s) uses bogus MAC length!", c->name, c->hostname);
			return false;
		}
	} else {
		c->indigest = NULL;
	}

	c->incompression = compression;

	c->allow_request = CHALLENGE;

	return send_challenge(c);
}

bool send_challenge(connection_t *c) {
	/* CHECKME: what is most reasonable value for len? */

	int len = RSA_size(c->rsa_key);

	/* Allocate buffers for the challenge */

	char buffer[2 * len + 1];

	c->hischallenge = xrealloc(c->hischallenge, len);

	/* Copy random data to the buffer */

	if(1 != RAND_bytes((unsigned char *)c->hischallenge, len)) {
		int err = ERR_get_error();
		logger(LOG_ERR, "Failed to generate challenge (%s)", ERR_error_string(err, NULL));
		return false; // Do not send predictable challenges, let connection attempt fail.
	}

	/* Convert to hex */

	bin2hex(c->hischallenge, buffer, len);
	buffer[len * 2] = '\0';

	/* Send the challenge */

	return send_request(c, "%d %s", CHALLENGE, buffer);
}

bool challenge_h(connection_t *c) {
	char buffer[MAX_STRING_SIZE];
	int len;

	if(sscanf(c->buffer, "%*d " MAX_STRING, buffer) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "CHALLENGE", c->name,
		       c->hostname);
		return false;
	}

	len = RSA_size(myself->connection->rsa_key);

	/* Check if the length of the challenge is all right */

	if(strlen(buffer) != (size_t)len * 2) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name,
		       c->hostname, "wrong challenge length");
		return false;
	}

	/* Allocate buffers for the challenge */

	c->mychallenge = xrealloc(c->mychallenge, len);

	/* Convert the challenge from hexadecimal back to binary */

	if(!hex2bin(buffer, c->mychallenge, len)) {
		logger(LOG_ERR, "Got bad %s from %s(%s): %s", "CHALLENGE", c->name, c->hostname, "invalid challenge");
		return false;
	}

	c->allow_request = CHAL_REPLY;

	/* Rest is done by send_chal_reply() */

	return send_chal_reply(c);
}

bool send_chal_reply(connection_t *c) {
	char hash[EVP_MAX_MD_SIZE * 2 + 1];
	EVP_MD_CTX *ctx;

	/* Calculate the hash from the challenge we received */

	ctx = EVP_MD_CTX_create();

	if(!ctx) {
		abort();
	}

	if(!EVP_DigestInit(ctx, c->indigest)
	                || !EVP_DigestUpdate(ctx, c->mychallenge, RSA_size(myself->connection->rsa_key))
	                || !EVP_DigestFinal(ctx, (unsigned char *)hash, NULL)) {
		EVP_MD_CTX_destroy(ctx);
		logger(LOG_ERR, "Error during calculation of response for %s (%s): %s",
		       c->name, c->hostname, ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	EVP_MD_CTX_destroy(ctx);

	/* Convert the hash to a hexadecimal formatted string */

	bin2hex(hash, hash, EVP_MD_size(c->indigest));
	hash[EVP_MD_size(c->indigest) * 2] = '\0';

	/* Send the reply */

	return send_request(c, "%d %s", CHAL_REPLY, hash);
}

bool chal_reply_h(connection_t *c) {
	char hishash[MAX_STRING_SIZE];
	char myhash[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *ctx;

	if(sscanf(c->buffer, "%*d " MAX_STRING, hishash) != 1) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "CHAL_REPLY", c->name,
		       c->hostname);
		return false;
	}

	/* Check if the length of the hash is all right */

	if(strlen(hishash) != (size_t)EVP_MD_size(c->outdigest) * 2) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name,
		       c->hostname, "wrong challenge reply length");
		return false;
	}

	/* Convert the hash to binary format */

	if(!hex2bin(hishash, hishash, EVP_MD_size(c->outdigest))) {
		logger(LOG_ERR, "Got bad %s from %s(%s): %s", "CHAL_REPLY", c->name, c->hostname, "invalid hash");
		return false;
	}

	/* Calculate the hash from the challenge we sent */

	ctx = EVP_MD_CTX_create();

	if(!ctx) {
		abort();
	}

	if(!EVP_DigestInit(ctx, c->outdigest)
	                || !EVP_DigestUpdate(ctx, c->hischallenge, RSA_size(c->rsa_key))
	                || !EVP_DigestFinal(ctx, (unsigned char *)myhash, NULL)) {
		EVP_MD_CTX_destroy(ctx);
		logger(LOG_ERR, "Error during calculation of response from %s (%s): %s",
		       c->name, c->hostname, ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	EVP_MD_CTX_destroy(ctx);

	/* Verify the incoming hash with the calculated hash */

	if(memcmp(hishash, myhash, EVP_MD_size(c->outdigest))) {
		logger(LOG_ERR, "Possible intruder %s (%s): %s", c->name,
		       c->hostname, "wrong challenge reply");

		ifdebug(SCARY_THINGS) {
			bin2hex(myhash, hishash, SHA_DIGEST_LENGTH);
			hishash[SHA_DIGEST_LENGTH * 2] = '\0';
			logger(LOG_DEBUG, "Expected challenge reply: %s", hishash);
		}

		return false;
	}

	/* Identity has now been positively verified.
	   Send an acknowledgement with the rest of the information needed.
	 */

	c->allow_request = ACK;

	return send_ack(c);
}

bool send_ack(connection_t *c) {
	/* ACK message contains rest of the information the other end needs
	   to create node_t and edge_t structures. */

	struct timeval now;
	bool choice;

	/* Estimate weight */

	gettimeofday(&now, NULL);
	c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;

	/* Check some options */

	if((get_config_bool(lookup_config(c->config_tree, "IndirectData"), &choice) && choice) || myself->options & OPTION_INDIRECT) {
		c->options |= OPTION_INDIRECT;
	}

	if((get_config_bool(lookup_config(c->config_tree, "TCPOnly"), &choice) && choice) || myself->options & OPTION_TCPONLY) {
		c->options |= OPTION_TCPONLY | OPTION_INDIRECT;
	}

	if(myself->options & OPTION_PMTU_DISCOVERY && !(c->options & OPTION_TCPONLY)) {
		c->options |= OPTION_PMTU_DISCOVERY;
	}

	choice = myself->options & OPTION_CLAMP_MSS;
	get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice);

	if(choice) {
		c->options |= OPTION_CLAMP_MSS;
	}

	get_config_int(lookup_config(c->config_tree, "Weight"), &c->estimated_weight);

	return send_request(c, "%d %s %d %x", ACK, myport, c->estimated_weight, c->options);
}

static void send_everything(connection_t *c) {
	avl_node_t *node, *node2;
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

bool ack_h(connection_t *c) {
	char hisport[MAX_STRING_SIZE];
	int weight, mtu;
	uint32_t options;
	node_t *n;
	bool choice;

	if(sscanf(c->buffer, "%*d " MAX_STRING " %d %x", hisport, &weight, &options) != 3) {
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
			ifdebug(CONNECTIONS) logger(LOG_DEBUG, "Established a second connection with %s (%s), closing old connection",
			                            n->name, n->hostname);
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

	if(get_config_int(lookup_config(c->config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
		n->mtu = mtu;
	}

	if(get_config_int(lookup_config(config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
		n->mtu = mtu;
	}

	if(get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice)) {
		if(choice) {
			c->options |= OPTION_CLAMP_MSS;
		} else {
			c->options &= ~OPTION_CLAMP_MSS;
		}
	}

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
	sockaddrcpy(&c->edge->address, &c->address);
	sockaddr_setport(&c->edge->address, hisport);
	c->edge->weight = (weight + c->estimated_weight) / 2;
	c->edge->connection = c;
	c->edge->options = c->options;

	edge_add(c->edge);

	/* Notify everyone of the new edge */

	if(tunnelserver) {
		send_add_edge(c, c->edge);
	} else {
		send_add_edge(everyone, c->edge);
	}

	/* Run MST and SSSP algorithms */

	graph();

	return true;
}
