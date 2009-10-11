/*
    net_setup.c -- Setup.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>

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

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "device.h"
#include "event.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "route.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

char *myport;

bool read_rsa_public_key(connection_t *c) {
	FILE *fp;
	char *fname;
	char *key;

	if(!c->rsa_key) {
		c->rsa_key = RSA_new();
//		RSA_blinding_on(c->rsa_key, NULL);
	}

	/* First, check for simple PublicKey statement */

	if(get_config_string(lookup_config(c->config_tree, "PublicKey"), &key)) {
		BN_hex2bn(&c->rsa_key->n, key);
		BN_hex2bn(&c->rsa_key->e, "FFFF");
		free(key);
		return true;
	}

	/* Else, check for PublicKeyFile statement and read it */

	if(get_config_string(lookup_config(c->config_tree, "PublicKeyFile"), &fname)) {
		fp = fopen(fname, "r");

		if(!fp) {
			logger(LOG_ERR, "Error reading RSA public key file `%s': %s",
				   fname, strerror(errno));
			free(fname);
			return false;
		}

		free(fname);
		c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);

		if(c->rsa_key)
			return true;		/* Woohoo. */

		/* If it fails, try PEM_read_RSA_PUBKEY. */
		fp = fopen(fname, "r");

		if(!fp) {
			logger(LOG_ERR, "Error reading RSA public key file `%s': %s",
				   fname, strerror(errno));
			free(fname);
			return false;
		}

		free(fname);
		c->rsa_key = PEM_read_RSA_PUBKEY(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);

		if(c->rsa_key) {
//				RSA_blinding_on(c->rsa_key, NULL);
			return true;
		}

		logger(LOG_ERR, "Reading RSA public key file `%s' failed: %s",
			   fname, strerror(errno));
		return false;
	}

	/* Else, check if a harnessed public key is in the config file */

	xasprintf(&fname, "%s/hosts/%s", confbase, c->name);
	fp = fopen(fname, "r");

	if(fp) {
		c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);
	}

	free(fname);

	if(c->rsa_key)
		return true;

	/* Try again with PEM_read_RSA_PUBKEY. */

	xasprintf(&fname, "%s/hosts/%s", confbase, c->name);
	fp = fopen(fname, "r");

	if(fp) {
		c->rsa_key = PEM_read_RSA_PUBKEY(fp, &c->rsa_key, NULL, NULL);
//		RSA_blinding_on(c->rsa_key, NULL);
		fclose(fp);
	}

	free(fname);

	if(c->rsa_key)
		return true;

	logger(LOG_ERR, "No public key for %s specified!", c->name);

	return false;
}

bool read_rsa_private_key(void) {
	FILE *fp;
	char *fname, *key, *pubkey;
	struct stat s;

	if(get_config_string(lookup_config(config_tree, "PrivateKey"), &key)) {
		if(!get_config_string(lookup_config(myself->connection->config_tree, "PublicKey"), &pubkey)) {
			logger(LOG_ERR, "PrivateKey used but no PublicKey found!");
			return false;
		}
		myself->connection->rsa_key = RSA_new();
//		RSA_blinding_on(myself->connection->rsa_key, NULL);
		BN_hex2bn(&myself->connection->rsa_key->d, key);
		BN_hex2bn(&myself->connection->rsa_key->n, pubkey);
		BN_hex2bn(&myself->connection->rsa_key->e, "FFFF");
		free(key);
		free(pubkey);
		return true;
	}

	if(!get_config_string(lookup_config(config_tree, "PrivateKeyFile"), &fname))
		xasprintf(&fname, "%s/rsa_key.priv", confbase);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading RSA private key file `%s': %s",
			   fname, strerror(errno));
		free(fname);
		return false;
	}

#if !defined(HAVE_MINGW) && !defined(HAVE_CYGWIN)
	if(fstat(fileno(fp), &s)) {
		logger(LOG_ERR, "Could not stat RSA private key file `%s': %s'",
				fname, strerror(errno));
		free(fname);
		return false;
	}

	if(s.st_mode & ~0100700)
		logger(LOG_WARNING, "Warning: insecure file permissions for RSA private key file `%s'!", fname);
#endif

	myself->connection->rsa_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if(!myself->connection->rsa_key) {
		logger(LOG_ERR, "Reading RSA private key file `%s' failed: %s",
			   fname, strerror(errno));
		free(fname);
		return false;
	}

	free(fname);
	return true;
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
bool setup_myself(void) {
	config_t *cfg;
	subnet_t *subnet;
	char *name, *hostname, *mode, *afname, *cipher, *digest;
	char *address = NULL;
	char *envp[5];
	struct addrinfo *ai, *aip, hint = {0};
	bool choice;
	int i, err;

	myself = new_node();
	myself->connection = new_connection();
	init_configuration(&myself->connection->config_tree);

	xasprintf(&myself->hostname, "MYSELF");
	xasprintf(&myself->connection->hostname, "MYSELF");

	myself->connection->options = 0;
	myself->connection->protocol_version = PROT_CURRENT;

	if(!get_config_string(lookup_config(config_tree, "Name"), &name)) {	/* Not acceptable */
		logger(LOG_ERR, "Name for tinc daemon required!");
		return false;
	}

	if(!check_id(name)) {
		logger(LOG_ERR, "Invalid name for myself!");
		free(name);
		return false;
	}

	myself->name = name;
	myself->connection->name = xstrdup(name);

	if(!read_connection_config(myself->connection)) {
		logger(LOG_ERR, "Cannot open host configuration file for myself!");
		return false;
	}

	if(!read_rsa_private_key())
		return false;

	if(!get_config_string(lookup_config(myself->connection->config_tree, "Port"), &myport))
		xasprintf(&myport, "655");

	/* Read in all the subnets specified in the host configuration file */

	cfg = lookup_config(myself->connection->config_tree, "Subnet");

	while(cfg) {
		if(!get_config_subnet(cfg, &subnet))
			return false;

		subnet_add(myself, subnet);

		cfg = lookup_config_next(myself->connection->config_tree, cfg);
	}

	/* Check some options */

	if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice) && choice)
		myself->options |= OPTION_INDIRECT;

	if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice) && choice)
		myself->options |= OPTION_TCPONLY;

	if(get_config_bool(lookup_config(myself->connection->config_tree, "IndirectData"), &choice) && choice)
		myself->options |= OPTION_INDIRECT;

	if(get_config_bool(lookup_config(myself->connection->config_tree, "TCPOnly"), &choice) && choice)
		myself->options |= OPTION_TCPONLY;

	if(myself->options & OPTION_TCPONLY)
		myself->options |= OPTION_INDIRECT;

	get_config_bool(lookup_config(config_tree, "TunnelServer"), &tunnelserver);

	if(get_config_string(lookup_config(config_tree, "Mode"), &mode)) {
		if(!strcasecmp(mode, "router"))
			routing_mode = RMODE_ROUTER;
		else if(!strcasecmp(mode, "switch"))
			routing_mode = RMODE_SWITCH;
		else if(!strcasecmp(mode, "hub"))
			routing_mode = RMODE_HUB;
		else {
			logger(LOG_ERR, "Invalid routing mode!");
			return false;
		}
		free(mode);
	} else
		routing_mode = RMODE_ROUTER;

	// Enable PMTUDiscovery by default if we are in router mode.

	choice = routing_mode == RMODE_ROUTER;
	get_config_bool(lookup_config(myself->connection->config_tree, "PMTUDiscovery"), &choice);
	if(choice)	
		myself->options |= OPTION_PMTU_DISCOVERY;

	get_config_bool(lookup_config(config_tree, "PriorityInheritance"), &priorityinheritance);

#if !defined(SOL_IP) || !defined(IP_TOS)
	if(priorityinheritance)
		logger(LOG_WARNING, "%s not supported on this platform", "PriorityInheritance");
#endif

	if(!get_config_int(lookup_config(config_tree, "MACExpire"), &macexpire))
		macexpire = 600;

	if(get_config_int(lookup_config(config_tree, "MaxTimeout"), &maxtimeout)) {
		if(maxtimeout <= 0) {
			logger(LOG_ERR, "Bogus maximum timeout!");
			return false;
		}
	} else
		maxtimeout = 900;

	if(get_config_string(lookup_config(config_tree, "AddressFamily"), &afname)) {
		if(!strcasecmp(afname, "IPv4"))
			addressfamily = AF_INET;
		else if(!strcasecmp(afname, "IPv6"))
			addressfamily = AF_INET6;
		else if(!strcasecmp(afname, "any"))
			addressfamily = AF_UNSPEC;
		else {
			logger(LOG_ERR, "Invalid address family!");
			return false;
		}
		free(afname);
	}

	get_config_bool(lookup_config(config_tree, "Hostnames"), &hostnames);

	/* Generate packet encryption key */

	if(get_config_string
	   (lookup_config(myself->connection->config_tree, "Cipher"), &cipher)) {
		if(!strcasecmp(cipher, "none")) {
			myself->incipher = NULL;
		} else {
			myself->incipher = EVP_get_cipherbyname(cipher);

			if(!myself->incipher) {
				logger(LOG_ERR, "Unrecognized cipher type!");
				return false;
			}
		}
	} else
		myself->incipher = EVP_bf_cbc();

	if(myself->incipher)
		myself->inkeylength = myself->incipher->key_len + myself->incipher->iv_len;
	else
		myself->inkeylength = 1;

	myself->connection->outcipher = EVP_bf_ofb();

	if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime))
		keylifetime = 3600;

	keyexpires = now + keylifetime;
	
	/* Check if we want to use message authentication codes... */

	if(get_config_string(lookup_config(myself->connection->config_tree, "Digest"), &digest)) {
		if(!strcasecmp(digest, "none")) {
			myself->indigest = NULL;
		} else {
			myself->indigest = EVP_get_digestbyname(digest);

			if(!myself->indigest) {
				logger(LOG_ERR, "Unrecognized digest type!");
				return false;
			}
		}
	} else
		myself->indigest = EVP_sha1();

	myself->connection->outdigest = EVP_sha1();

	if(get_config_int(lookup_config(myself->connection->config_tree, "MACLength"), &myself->inmaclength)) {
		if(myself->indigest) {
			if(myself->inmaclength > myself->indigest->md_size) {
				logger(LOG_ERR, "MAC length exceeds size of digest!");
				return false;
			} else if(myself->inmaclength < 0) {
				logger(LOG_ERR, "Bogus MAC length!");
				return false;
			}
		}
	} else
		myself->inmaclength = 4;

	myself->connection->outmaclength = 0;

	/* Compression */

	if(get_config_int(lookup_config(myself->connection->config_tree, "Compression"), &myself->incompression)) {
		if(myself->incompression < 0 || myself->incompression > 11) {
			logger(LOG_ERR, "Bogus compression level!");
			return false;
		}
	} else
		myself->incompression = 0;

	myself->connection->outcompression = 0;

	/* Done */

	myself->nexthop = myself;
	myself->via = myself;
	myself->status.reachable = true;
	node_add(myself);

	graph();

	/* Open device */

	if(!setup_device())
		return false;

	/* Run tinc-up script to further initialize the tap interface */
	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	execute_script("tinc-up", envp);

	for(i = 0; i < 5; i++)
		free(envp[i]);

	/* Run subnet-up scripts for our own subnets */

	subnet_update(myself, NULL, true);

	/* Open sockets */

	get_config_string(lookup_config(config_tree, "BindToAddress"), &address);

	hint.ai_family = addressfamily;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_flags = AI_PASSIVE;

	err = getaddrinfo(address, myport, &hint, &ai);

	if(err || !ai) {
		logger(LOG_ERR, "System call `%s' failed: %s", "getaddrinfo",
			   gai_strerror(err));
		return false;
	}

	listen_sockets = 0;

	for(aip = ai; aip; aip = aip->ai_next) {
		listen_socket[listen_sockets].tcp =
			setup_listen_socket((sockaddr_t *) aip->ai_addr);

		if(listen_socket[listen_sockets].tcp < 0)
			continue;

		listen_socket[listen_sockets].udp =
			setup_vpn_in_socket((sockaddr_t *) aip->ai_addr);

		if(listen_socket[listen_sockets].udp < 0)
			continue;

		ifdebug(CONNECTIONS) {
			hostname = sockaddr2hostname((sockaddr_t *) aip->ai_addr);
			logger(LOG_NOTICE, "Listening on %s", hostname);
			free(hostname);
		}

		memcpy(&listen_socket[listen_sockets].sa, aip->ai_addr, aip->ai_addrlen);
		listen_sockets++;
	}

	freeaddrinfo(ai);

	if(listen_sockets)
		logger(LOG_NOTICE, "Ready");
	else {
		logger(LOG_ERR, "Unable to create any listening socket!");
		return false;
	}

	return true;
}

/*
  initialize network
*/
bool setup_network(void) {
	now = time(NULL);

	init_events();
	init_connections();
	init_subnets();
	init_nodes();
	init_edges();
	init_requests();

	if(get_config_int(lookup_config(config_tree, "PingInterval"), &pinginterval)) {
		if(pinginterval < 1) {
			pinginterval = 86400;
		}
	} else
		pinginterval = 60;

	if(!get_config_int(lookup_config(config_tree, "PingTimeout"), &pingtimeout))
		pingtimeout = 5;
	if(pingtimeout < 1 || pingtimeout > pinginterval)
		pingtimeout = pinginterval;

	if(!get_config_int(lookup_config(config_tree, "MaxOutputBufferSize"), &maxoutbufsize))
		maxoutbufsize = 10 * MTU;

	if(!setup_myself())
		return false;

	return true;
}

/*
  close all open network connections
*/
void close_network_connections(void) {
	avl_node_t *node, *next;
	connection_t *c;
	char *envp[5];
	int i;

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;
		c->outgoing = false;
		terminate_connection(c, false);
	}

	list_delete_list(outgoing_list);

	if(myself && myself->connection) {
		subnet_update(myself, NULL, false);
		terminate_connection(myself->connection, false);
		free_connection(myself->connection);
	}

	for(i = 0; i < listen_sockets; i++) {
		close(listen_socket[i].tcp);
		close(listen_socket[i].udp);
	}

	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	exit_requests();
	exit_edges();
	exit_subnets();
	exit_nodes();
	exit_connections();
	exit_events();

	execute_script("tinc-down", envp);

	if(myport) free(myport);

	for(i = 0; i < 4; i++)
		free(envp[i]);

	close_device();

	return;
}
