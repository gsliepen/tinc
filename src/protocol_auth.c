/*
    protocol_auth.c -- handle the meta-protocol, authentication
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include "conf.h"
#include "connection.h"
#include "control.h"
#include "control_common.h"
#include "cipher.h"
#include "digest.h"
#include "ecdsa.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "rsa.h"
#include "script.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"
#include "random.h"
#include "compression.h"
#include "proxy.h"
#include "address_cache.h"

#include "ed25519/sha512.h"
#include "keys.h"

/* If nonzero, use null ciphers and skip all key exchanges. */
bool bypass_security = false;

int invitation_lifetime;
ecdsa_t *invitation_key = NULL;

static bool send_proxyrequest(connection_t *c) {
	switch(proxytype) {
	case PROXY_HTTP: {
		char *host;
		char *port;

		sockaddr2str(&c->address, &host, &port);
		send_request(c, "CONNECT %s:%s HTTP/1.1\r\n\r", host, port);
		free(host);
		free(port);
		return true;
	}

	case PROXY_SOCKS4:
	case PROXY_SOCKS5: {
		size_t reqlen = socks_req_len(proxytype, &c->address);
		uint8_t *req = alloca(reqlen);
		c->tcplen = create_socks_req(proxytype, req, &c->address);
		return c->tcplen ? send_meta(c, req, reqlen) : false;
	}

	case PROXY_SOCKS4A:
		logger(DEBUG_ALWAYS, LOG_ERR, "Proxy type not implemented yet");
		return false;

	case PROXY_EXEC:
		return true;

	case PROXY_NONE:
	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type");
		return false;
	}
}

bool send_id(connection_t *c) {
	gettimeofday(&c->start, NULL);

	int minor = 0;

	if(experimental) {
		if(c->outgoing && !ecdsa_active(c->ecdsa) && !(c->ecdsa = read_ecdsa_public_key(&c->config_tree, c->name))) {
			minor = 1;
		} else {
			minor = myself->connection->protocol_minor;
		}
	}

	if(proxytype && c->outgoing)
		if(!send_proxyrequest(c)) {
			return false;
		}

	return send_request(c, "%d %s %d.%d", ID, myself->connection->name, myself->connection->protocol_major, minor);
}

static bool finalize_invitation(connection_t *c, const char *data, uint16_t len) {
	(void)len;

	if(strchr(data, '\n')) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Received invalid key from invited node %s (%s)!\n", c->name, c->hostname);
		return false;
	}

	// Create a new host config file
	char filename[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "hosts" SLASH "%s", confbase, c->name);

	if(!access(filename, F_OK)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Host config file for %s (%s) already exists!\n", c->name, c->hostname);
		return false;
	}

	FILE *f = fopen(filename, "w");

	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error trying to create %s: %s\n", filename, strerror(errno));
		return false;
	}

	fprintf(f, "Ed25519PublicKey = %s\n", data);
	fclose(f);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Key successfully received from %s (%s)", c->name, c->hostname);

	if(!c->node) {
		c->node = lookup_node(c->name);
	}

	if(!c->node) {
		c->node = new_node(c->name);
		c->node->connection = c;
		node_add(c->node);
	}

	if(!c->node->address_cache) {
		c->node->address_cache = open_address_cache(c->node);
	}

	add_recent_address(c->node->address_cache, &c->address);

	// Call invitation-accepted script
	environment_t env;
	char *address, *port;

	environment_init(&env);
	environment_add(&env, "NODE=%s", c->name);
	sockaddr2str(&c->address, &address, &port);
	environment_add(&env, "REMOTEADDRESS=%s", address);
	environment_add(&env, "NAME=%s", myself->name);

	free(address);
	free(port);

	execute_script("invitation-accepted", &env);

	environment_exit(&env);

	sptps_send_record(&c->sptps, 2, data, 0);
	return true;
}

static bool receive_invitation_sptps(void *handle, uint8_t type, const void *data, uint16_t len) {
	connection_t *c = handle;

	if(type == 128) {
		return true;
	}

	if(type == 1 && c->status.invitation_used) {
		return finalize_invitation(c, data, len);
	}

	if(type != 0 || len != 18 || c->status.invitation_used) {
		return false;
	}

	// Recover the filename from the cookie and the key
	char *fingerprint = ecdsa_get_base64_public_key(invitation_key);
	const size_t hashbuflen = 18 + strlen(fingerprint);
	char *hashbuf = alloca(hashbuflen);
	char cookie[64];
	memcpy(hashbuf, data, 18);
	memcpy(hashbuf + 18, fingerprint, hashbuflen - 18);
	sha512(hashbuf, hashbuflen, cookie);
	b64encode_tinc_urlsafe(cookie, cookie, 18);
	free(fingerprint);

	char filename[PATH_MAX], usedname[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "invitations" SLASH "%s", confbase, cookie);
	snprintf(usedname, sizeof(usedname), "%s" SLASH "invitations" SLASH "%s.used", confbase, cookie);

	// Atomically rename the invitation file
	if(rename(filename, usedname)) {
		if(errno == ENOENT) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s tried to use non-existing invitation %s\n", c->hostname, cookie);
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error trying to rename invitation %s\n", cookie);
		}

		return false;
	}

	// Check the timestamp of the invitation
	struct stat st;

	if(stat(usedname, &st)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat %s", usedname);
		return false;
	}

	if(st.st_mtime + invitation_lifetime < now.tv_sec) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s tried to use expired invitation %s", c->hostname, cookie);
		return false;
	}

	// Open the renamed file
	FILE *f = fopen(usedname, "r");

	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error trying to open invitation %s\n", cookie);
		return false;
	}

	// Read the new node's Name from the file
	char buf[1024] = "";

	if(!fgets(buf, sizeof(buf), f)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not read invitation file %s\n", cookie);
		fclose(f);
		return false;
	}

	size_t buflen = strlen(buf);

	// Strip whitespace at the end
	while(buflen && strchr(" \t\r\n", buf[buflen - 1])) {
		buf[--buflen] = 0;
	}

	// Split the first line into variable and value
	len = strcspn(buf, " \t=");
	char *name = buf + len;
	name += strspn(name, " \t");

	if(*name == '=') {
		name++;
		name += strspn(name, " \t");
	}

	buf[len] = 0;

	// Check that it is a valid Name
	if(!*buf || !*name || strcasecmp(buf, "Name") || !check_id(name) || !strcmp(name, myself->name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid invitation file %s\n", cookie);
		fclose(f);
		return false;
	}

	free(c->name);
	c->name = xstrdup(name);

	// Send the node the contents of the invitation file
	rewind(f);
	size_t result;

	while((result = fread(buf, 1, sizeof(buf), f))) {
		sptps_send_record(&c->sptps, 0, buf, result);
	}

	if(!feof(f)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not read invitation file %s\n", cookie);
		fclose(f);
		return false;
	}

	sptps_send_record(&c->sptps, 1, buf, 0);
	fclose(f);
	unlink(usedname);

	c->status.invitation_used = true;

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Invitation %s successfully sent to %s (%s)", cookie, c->name, c->hostname);
	return true;
}

bool id_h(connection_t *c, const char *request) {
	char name[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING " %2d.%3d", name, &c->protocol_major, &c->protocol_minor) < 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ID", c->name,
		       c->hostname);
		return false;
	}

	/* Check if this is a control connection */

	if(name[0] == '^' && !strcmp(name + 1, controlcookie)) {
		c->status.control = true;
		c->allow_request = CONTROL;
		c->last_ping_time = now.tv_sec + 3600;

		free(c->name);
		c->name = xstrdup("<control>");

		if(!c->outgoing) {
			send_id(c);
		}

		return send_request(c, "%d %d %d", ACK, TINC_CTL_VERSION_CURRENT, getpid());
	}

	if(name[0] == '?') {
		if(!invitation_key) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got invitation from %s but we don't have an invitation key", c->hostname);
			return false;
		}

		c->ecdsa = ecdsa_set_base64_public_key(name + 1);

		if(!c->ecdsa) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad invitation from %s", c->hostname);
			return false;
		}

		c->status.invitation = true;
		char *mykey = ecdsa_get_base64_public_key(invitation_key);

		if(!mykey) {
			return false;
		}

		if(!c->outgoing) {
			send_id(c);
		}

		if(!send_request(c, "%d %s", ACK, mykey)) {
			return false;
		}

		free(mykey);

		c->protocol_minor = 2;

		return sptps_start(&c->sptps, c, false, false, invitation_key, c->ecdsa, "tinc invitation", 15, send_meta_sptps, receive_invitation_sptps);
	}

	/* Check if identity is a valid name */

	if(!check_id(name) || !strcmp(name, myself->name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ID", c->name,
		       c->hostname, "invalid name");
		return false;
	}

	/* If this is an outgoing connection, make sure we are connected to the right host */

	if(c->outgoing) {
		if(strcmp(c->name, name)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s is %s instead of %s", c->hostname, name,
			       c->name);
			return false;
		}
	} else {
		free(c->name);
		c->name = xstrdup(name);
	}

	/* Check if version matches */

	if(c->protocol_major != myself->connection->protocol_major) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s (%s) uses incompatible version %d.%d",
		       c->name, c->hostname, c->protocol_major, c->protocol_minor);
		return false;
	}

	if(bypass_security) {
		if(!c->config_tree) {
			c->config_tree = create_configuration();
		}

		c->allow_request = ACK;

		if(!c->outgoing) {
			send_id(c);
		}

		return send_ack(c);
	}

	if(!experimental) {
		c->protocol_minor = 0;
	}

	if(!c->config_tree) {
		c->config_tree = create_configuration();

		if(!read_host_config(c->config_tree, c->name, false)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s had unknown identity (%s)", c->hostname, c->name);
			return false;
		}

		if(experimental && !ecdsa_active(c->ecdsa)) {
			c->ecdsa = read_ecdsa_public_key(&c->config_tree, c->name);
		}

		/* Ignore failures if no key known yet */
	}

	if(c->protocol_minor && !ecdsa_active(c->ecdsa)) {
		c->protocol_minor = 1;
	}

	/* Forbid version rollback for nodes whose Ed25519 key we know */

	if(ecdsa_active(c->ecdsa) && c->protocol_minor < 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s (%s) tries to roll back protocol version to %d.%d",
		       c->name, c->hostname, c->protocol_major, c->protocol_minor);
		return false;
	}

	c->allow_request = METAKEY;

	if(!c->outgoing) {
		send_id(c);
	}

	if(c->protocol_minor >= 2) {
		c->allow_request = ACK;

		const size_t labellen = 25 + strlen(myself->name) + strlen(c->name);
		char *label = alloca(labellen);

		if(c->outgoing) {
			snprintf(label, labellen, "tinc TCP key expansion %s %s", myself->name, c->name);
		} else {
			snprintf(label, labellen, "tinc TCP key expansion %s %s", c->name, myself->name);
		}

		return sptps_start(&c->sptps, c, c->outgoing, false, myself->connection->ecdsa, c->ecdsa, label, labellen, send_meta_sptps, receive_meta_sptps);
	} else {
		return send_metakey(c);
	}
}

#ifndef DISABLE_LEGACY
static const char *get_cipher_name(cipher_t *cipher) {
	size_t keylen = cipher_keylength(cipher);

	if(keylen <= 16) {
		return "aes-128-cfb";
	} else if(keylen <= 24) {
		return "aes-192-cfb";
	} else {
		return "aes-256-cfb";
	}
}

bool send_metakey(connection_t *c) {
	if(!myself->connection->legacy) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Peer %s (%s) uses legacy protocol which we don't support", c->name, c->hostname);
		return false;
	}

	rsa_t *rsa = read_rsa_public_key(c->config_tree, c->name);

	if(!rsa) {
		return false;
	}

	legacy_ctx_t *ctx = new_legacy_ctx(rsa);

	/* We need to use a stream mode for the meta protocol. Use AES for this,
	   but try to match the key size with the one from the cipher selected
	   by Cipher.
	*/

	const char *cipher_name = get_cipher_name(myself->incipher);

	if(!init_crypto_by_name(&ctx->out, cipher_name, "sha256")) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during initialisation of cipher or digest to %s (%s)", c->name, c->hostname);
		free_legacy_ctx(ctx);
		return false;
	}

	const size_t len = rsa_size(ctx->rsa);
	const size_t hexkeylen = HEX_SIZE(len);
	char *key = alloca(len);
	char *enckey = alloca(len);
	char *hexkey = alloca(hexkeylen);

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

	if(!cipher_set_key_from_rsa(&ctx->out.cipher, key, len, true)) {
		free_legacy_ctx(ctx);
		memzero(key, len);
		return false;
	}

	if(debug_level >= DEBUG_SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Generated random meta key (unencrypted): %s", hexkey);
		memzero(hexkey, hexkeylen);
	}

	/* Encrypt the random data

	   We do not use one of the PKCS padding schemes here.
	   This is allowed, because we encrypt a totally random string
	   with a length equal to that of the modulus of the RSA key.
	 */

	bool encrypted = rsa_public_encrypt(ctx->rsa, key, len, enckey);
	memzero(key, len);

	if(!encrypted) {
		free_legacy_ctx(ctx);
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during encryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	free_legacy_ctx(c->legacy);
	c->legacy = ctx;

	/* Convert the encrypted random data to a hexadecimal formatted string */

	bin2hex(enckey, hexkey, len);

	/* Send the meta key */

	bool result = send_request(c, "%d %d %d %d %d %s", METAKEY,
	                           cipher_get_nid(&c->legacy->out.cipher),
	                           digest_get_nid(&c->legacy->out.digest), c->outmaclength,
	                           COMPRESS_NONE, hexkey);

	c->status.encryptout = true;
	return result;
}

bool metakey_h(connection_t *c, const char *request) {
	if(!myself->connection->legacy || !c->legacy) {
		return false;
	}

	char hexkey[MAX_STRING_SIZE];
	int cipher, digest;
	const size_t len = rsa_size(myself->connection->legacy->rsa);
	char *enckey = alloca(len);
	char *key = alloca(len);

	if(sscanf(request, "%*d %d %d %*d %*d " MAX_STRING, &cipher, &digest, hexkey) != 3) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "METAKEY", c->name, c->hostname);
		return false;
	}

	if(!cipher || !digest) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): cipher %d, digest %d", c->name, c->hostname, cipher, digest);
		return false;
	}

	/* Convert the challenge from hexadecimal back to binary */

	size_t inlen = hex2bin(hexkey, enckey, len);

	/* Check if the length of the meta key is all right */

	if(inlen != len) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong keylength");
		return false;
	}

	/* Decrypt the meta key */

	if(!rsa_private_decrypt(myself->connection->legacy->rsa, enckey, len, key)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during decryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	if(debug_level >= DEBUG_SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Received random meta key (unencrypted): %s", hexkey);
		// Hopefully the user knew what he was doing leaking session keys into logs. We'll do the right thing here anyway.
		memzero(hexkey, HEX_SIZE(len));
	}

	/* Check and lookup cipher and digest algorithms */

	if(!init_crypto_by_nid(&c->legacy->in, cipher, digest)) {
		memzero(key, len);
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during initialisation of cipher or digest from %s (%s)", c->name, c->hostname);
		return false;
	}

	bool key_set = cipher_set_key_from_rsa(&c->legacy->in.cipher, key, len, false);
	memzero(key, len);

	if(!key_set) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error setting RSA key for %s (%s)", c->name, c->hostname);
		return false;
	}

	c->status.decryptin = true;

	c->allow_request = CHALLENGE;

	return send_challenge(c);
}

bool send_challenge(connection_t *c) {
	const size_t len = rsa_size(c->legacy->rsa);
	char *buffer = alloca(len * 2 + 1);

	c->hischallenge = xrealloc(c->hischallenge, len);

	/* Copy random data to the buffer */

	randomize(c->hischallenge, len);

	/* Convert to hex */

	bin2hex(c->hischallenge, buffer, len);

	/* Send the challenge */

	return send_request(c, "%d %s", CHALLENGE, buffer);
}

bool challenge_h(connection_t *c, const char *request) {
	if(!myself->connection->legacy) {
		return false;
	}

	char buffer[MAX_STRING_SIZE];
	const size_t len = rsa_size(myself->connection->legacy->rsa);

	if(sscanf(request, "%*d " MAX_STRING, buffer) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "CHALLENGE", c->name, c->hostname);
		return false;
	}

	/* Check if the length of the challenge is all right */

	if(strlen(buffer) != (size_t)len * 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge length");
		return false;
	}

	c->mychallenge = xrealloc(c->mychallenge, len);

	/* Convert the challenge from hexadecimal back to binary */

	hex2bin(buffer, c->mychallenge, len);

	/* The rest is done by send_chal_reply() */

	c->allow_request = CHAL_REPLY;

	if(c->outgoing) {
		return send_chal_reply(c);
	} else {
		return true;
	}
}

bool send_chal_reply(connection_t *c) {
	const size_t len = rsa_size(myself->connection->legacy->rsa);
	size_t digestlen = digest_length(&c->legacy->in.digest);
	char *digest = alloca(digestlen * 2 + 1);

	/* Calculate the hash from the challenge we received */

	if(!digest_create(&c->legacy->in.digest, c->mychallenge, len, digest)) {
		return false;
	}

	free(c->mychallenge);
	c->mychallenge = NULL;

	/* Convert the hash to a hexadecimal formatted string */

	bin2hex(digest, digest, digestlen);

	/* Send the reply */

	return send_request(c, "%d %s", CHAL_REPLY, digest);
}

bool chal_reply_h(connection_t *c, const char *request) {
	char hishash[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, hishash) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "CHAL_REPLY", c->name,
		       c->hostname);
		return false;
	}

	/* Convert the hash to binary format */

	size_t inlen = hex2bin(hishash, hishash, sizeof(hishash));

	/* Check if the length of the hash is all right */

	if(inlen != digest_length(&c->legacy->out.digest)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply length");
		return false;
	}


	/* Verify the hash */

	if(!digest_verify(&c->legacy->out.digest, c->hischallenge, rsa_size(c->legacy->rsa), hishash)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply");
		return false;
	}

	/* Identity has now been positively verified.
	   Send an acknowledgement with the rest of the information needed.
	 */

	free(c->hischallenge);
	c->hischallenge = NULL;
	c->allow_request = ACK;

	if(!c->outgoing) {
		send_chal_reply(c);
	}

	return send_ack(c);
}

static bool send_upgrade(connection_t *c) {
	/* Special case when protocol_minor is 1: the other end is Ed25519 capable,
	 * but doesn't know our key yet. So send it now. */

	char *pubkey = ecdsa_get_base64_public_key(myself->connection->ecdsa);

	if(!pubkey) {
		return false;
	}

	bool result = send_request(c, "%d %s", ACK, pubkey);
	free(pubkey);
	return result;
}
#else
bool send_metakey(connection_t *c) {
	(void)c;
	return false;
}

bool metakey_h(connection_t *c, const char *request) {
	(void)c;
	(void)request;
	return false;
}

bool send_challenge(connection_t *c) {
	(void)c;
	return false;
}

bool challenge_h(connection_t *c, const char *request) {
	(void)c;
	(void)request;
	return false;
}

bool send_chal_reply(connection_t *c) {
	(void)c;
	return false;
}

bool chal_reply_h(connection_t *c, const char *request) {
	(void)c;
	(void)request;
	return false;
}

static bool send_upgrade(connection_t *c) {
	(void)c;
	return false;
}
#endif

bool send_ack(connection_t *c) {
	if(c->protocol_minor == 1) {
		return send_upgrade(c);
	}

	/* ACK message contains rest of the information the other end needs
	   to create node_t and edge_t structures. */

	struct timeval now;
	bool choice;

	/* Estimate weight */

	gettimeofday(&now, NULL);
	c->estimated_weight = (int)((now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000);

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

	if(!get_config_int(lookup_config(c->config_tree, "Weight"), &c->estimated_weight)) {
		get_config_int(lookup_config(&config_tree, "Weight"), &c->estimated_weight);
	}

	return send_request(c, "%d %s %d %x", ACK, myport.udp, c->estimated_weight, (c->options & 0xffffff) | (experimental ? (PROT_MINOR << 24) : 0));
}

static void send_everything(connection_t *c) {
	/* Send all known subnets and edges */

	if(disablebuggypeers) {
		static struct {
			vpn_packet_t pkt;
			char pad[MAXBUFSIZE - MAXSIZE];
		} zeropkt;

		memset(&zeropkt, 0, sizeof(zeropkt));
		zeropkt.pkt.len = MAXBUFSIZE;
		send_tcppacket(c, &zeropkt.pkt);
	}

	if(tunnelserver) {
		for splay_each(subnet_t, s, &myself->subnet_tree) {
			send_add_subnet(c, s);
		}

		return;
	}

	for splay_each(node_t, n, &node_tree) {
		for splay_each(subnet_t, s, &n->subnet_tree) {
			send_add_subnet(c, s);
		}

		for splay_each(edge_t, e, &n->edge_tree) {
			send_add_edge(c, e);
		}
	}
}

static bool upgrade_h(connection_t *c, const char *request) {
	char pubkey[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, pubkey) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name, c->hostname);
		return false;
	}

	if(ecdsa_active(c->ecdsa) || (c->ecdsa = read_ecdsa_public_key(&c->config_tree, c->name))) {
		char *knownkey = ecdsa_get_base64_public_key(c->ecdsa);
		bool different = strcmp(knownkey, pubkey);
		free(knownkey);

		if(different) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Already have an Ed25519 public key from %s (%s) which is different from the one presented now!", c->name, c->hostname);
			return false;
		}

		logger(DEBUG_ALWAYS, LOG_INFO, "Already have Ed25519 public key from %s (%s), ignoring.", c->name, c->hostname);
		c->allow_request = TERMREQ;
		return send_termreq(c);
	}

	c->ecdsa = ecdsa_set_base64_public_key(pubkey);

	if(!c->ecdsa) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Got bad Ed25519 public key from %s (%s), not upgrading.", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Got Ed25519 public key from %s (%s), upgrading!", c->name, c->hostname);
	append_config_file(c->name, "Ed25519PublicKey", pubkey);
	c->allow_request = TERMREQ;

	if(c->outgoing) {
		c->outgoing->timeout = 0;
	}

	return send_termreq(c);
}

bool ack_h(connection_t *c, const char *request) {
	if(c->protocol_minor == 1) {
		return upgrade_h(c, request);
	}

	char hisport[MAX_STRING_SIZE];
	int weight, mtu;
	uint32_t options;
	node_t *n;
	bool choice;

	if(sscanf(request, "%*d " MAX_STRING " %d %x", hisport, &weight, &options) != 3) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name,
		       c->hostname);
		return false;
	}

	/* Check if we already have a node_t for him */

	n = lookup_node(c->name);

	if(!n) {
		n = new_node(c->name);
		node_add(n);
	} else {
		if(n->connection) {
			/* Oh dear, we already have a connection to this node. */
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Established a second connection with %s (%s), closing old connection", n->connection->name, n->connection->hostname);

			if(n->connection->outgoing) {
				if(c->outgoing) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Two outgoing connections to the same node!");
				} else {
					c->outgoing = n->connection->outgoing;
				}

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

	if(get_config_int(lookup_config(c->config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
		n->mtu = mtu;
	}

	if(get_config_int(lookup_config(&config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
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

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection with %s (%s) activated", c->name,
	       c->hostname);

	/* Send him everything we know */

	send_everything(c);

	/* Create an edge_t for this connection */

	c->edge = new_edge();
	c->edge->from = myself;
	c->edge->to = n;
	sockaddrcpy(&c->edge->address, &c->address);
	sockaddr_setport(&c->edge->address, hisport);
	sockaddr_t local_sa;
	socklen_t local_salen = sizeof(local_sa);

	if(getsockname(c->socket, &local_sa.sa, &local_salen) < 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Could not get local socket address for connection with %s", c->name);
	} else {
		sockaddr_setport(&local_sa, myport.udp);
		c->edge->local_address = local_sa;
	}

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
