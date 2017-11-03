/*
    net_setup.c -- Setup.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>
                  2010      Brandon Black <blblack@gmail.com>

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
#include "proxy.h"
#include "route.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

char *myport;
devops_t devops;

#ifndef HAVE_RSA_SET0_KEY
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
	BN_free(r->n);
	r->n = n;
	BN_free(r->e);
	r->e = e;
	BN_free(r->d);
	r->d = d;
	return 1;
}
#endif

bool read_rsa_public_key(connection_t *c) {
	FILE *fp;
	char *pubname;
	char *hcfname;
	char *key;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;

	if(!c->rsa_key) {
		c->rsa_key = RSA_new();
//		RSA_blinding_on(c->rsa_key, NULL);
	}

	/* First, check for simple PublicKey statement */

	if(get_config_string(lookup_config(c->config_tree, "PublicKey"), &key)) {
		if((size_t)BN_hex2bn(&n, key) != strlen(key)) {
			free(key);
			logger(LOG_ERR, "Invalid PublicKey for %s!", c->name);
			return false;
		}

		free(key);
		BN_hex2bn(&e, "FFFF");

		if(!n || !e || RSA_set0_key(c->rsa_key, n, e, NULL) != 1) {
			BN_free(e);
			BN_free(n);
			logger(LOG_ERR, "RSA_set0_key() failed with PublicKey for %s!", c->name);
			return false;
		}

		return true;
	}

	/* Else, check for PublicKeyFile statement and read it */

	if(get_config_string(lookup_config(c->config_tree, "PublicKeyFile"), &pubname)) {
		fp = fopen(pubname, "r");

		if(!fp) {
			logger(LOG_ERR, "Error reading RSA public key file `%s': %s", pubname, strerror(errno));
			free(pubname);
			return false;
		}

		c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);

		if(c->rsa_key) {
			free(pubname);
			return true;            /* Woohoo. */
		}

		/* If it fails, try PEM_read_RSA_PUBKEY. */
		fp = fopen(pubname, "r");

		if(!fp) {
			logger(LOG_ERR, "Error reading RSA public key file `%s': %s", pubname, strerror(errno));
			free(pubname);
			return false;
		}

		c->rsa_key = PEM_read_RSA_PUBKEY(fp, &c->rsa_key, NULL, NULL);
		fclose(fp);

		if(c->rsa_key) {
//				RSA_blinding_on(c->rsa_key, NULL);
			free(pubname);
			return true;
		}

		logger(LOG_ERR, "Reading RSA public key file `%s' failed: %s", pubname, strerror(errno));
		free(pubname);
		return false;
	}

	/* Else, check if a harnessed public key is in the config file */

	xasprintf(&hcfname, "%s/hosts/%s", confbase, c->name);
	fp = fopen(hcfname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading RSA public key file `%s': %s", hcfname, strerror(errno));
		free(hcfname);
		return false;
	}

	c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
	fclose(fp);

	if(c->rsa_key) {
		free(hcfname);
		return true;
	}

	/* Try again with PEM_read_RSA_PUBKEY. */

	fp = fopen(hcfname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading RSA public key file `%s': %s", hcfname, strerror(errno));
		free(hcfname);
		return false;
	}

	free(hcfname);
	c->rsa_key = PEM_read_RSA_PUBKEY(fp, &c->rsa_key, NULL, NULL);
//	RSA_blinding_on(c->rsa_key, NULL);
	fclose(fp);

	if(c->rsa_key) {
		return true;
	}

	logger(LOG_ERR, "No public key for %s specified!", c->name);

	return false;
}

static bool read_rsa_private_key(void) {
	FILE *fp;
	char *fname, *key, *pubkey;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	BIGNUM *d = NULL;

	if(get_config_string(lookup_config(config_tree, "PrivateKey"), &key)) {
		myself->connection->rsa_key = RSA_new();

//		RSA_blinding_on(myself->connection->rsa_key, NULL);
		if((size_t)BN_hex2bn(&d, key) != strlen(key)) {
			logger(LOG_ERR, "Invalid PrivateKey for myself!");
			free(key);
			return false;
		}

		free(key);

		if(!get_config_string(lookup_config(config_tree, "PublicKey"), &pubkey)) {
			BN_free(d);
			logger(LOG_ERR, "PrivateKey used but no PublicKey found!");
			return false;
		}

		if((size_t)BN_hex2bn(&n, pubkey) != strlen(pubkey)) {
			free(pubkey);
			BN_free(d);
			logger(LOG_ERR, "Invalid PublicKey for myself!");
			return false;
		}

		free(pubkey);
		BN_hex2bn(&e, "FFFF");

		if(!n || !e || !d || RSA_set0_key(myself->connection->rsa_key, n, e, d) != 1) {
			BN_free(d);
			BN_free(e);
			BN_free(n);
			logger(LOG_ERR, "RSA_set0_key() failed with PrivateKey for myself!");
			return false;
		}

		return true;
	}

	if(!get_config_string(lookup_config(config_tree, "PrivateKeyFile"), &fname)) {
		xasprintf(&fname, "%s/rsa_key.priv", confbase);
	}

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading RSA private key file `%s': %s",
		       fname, strerror(errno));
		free(fname);
		return false;
	}

#if !defined(HAVE_MINGW) && !defined(HAVE_CYGWIN)
	struct stat s;

	if(!fstat(fileno(fp), &s)) {
		if(s.st_mode & ~0100700) {
			logger(LOG_WARNING, "Warning: insecure file permissions for RSA private key file `%s'!", fname);
		}
	} else {
		logger(LOG_WARNING, "Could not stat RSA private key file `%s': %s'", fname, strerror(errno));
	}

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
  Read Subnets from all host config files
*/
void load_all_subnets(void) {
	DIR *dir;
	struct dirent *ent;
	char *dname;
	char *fname;
	avl_tree_t *config_tree;
	config_t *cfg;
	subnet_t *s, *s2;
	node_t *n;

	xasprintf(&dname, "%s/hosts", confbase);
	dir = opendir(dname);

	if(!dir) {
		logger(LOG_ERR, "Could not open %s: %s", dname, strerror(errno));
		free(dname);
		return;
	}

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name)) {
			continue;
		}

		n = lookup_node(ent->d_name);
#ifdef _DIRENT_HAVE_D_TYPE
		//if(ent->d_type != DT_REG)
		//      continue;
#endif

		xasprintf(&fname, "%s/hosts/%s", confbase, ent->d_name);
		init_configuration(&config_tree);
		read_config_options(config_tree, ent->d_name);
		read_config_file(config_tree, fname);
		free(fname);

		if(!n) {
			n = new_node();
			n->name = xstrdup(ent->d_name);
			node_add(n);
		}

		for(cfg = lookup_config(config_tree, "Subnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			if(!get_config_subnet(cfg, &s)) {
				continue;
			}

			if((s2 = lookup_subnet(n, s))) {
				s2->expires = -1;
			} else {
				subnet_add(n, s);
			}
		}

		exit_configuration(&config_tree);
	}

	closedir(dir);
}

char *get_name(void) {
	char *name = NULL;

	get_config_string(lookup_config(config_tree, "Name"), &name);

	if(!name) {
		return NULL;
	}

	if(*name == '$') {
		char *envname = getenv(name + 1);
		char hostname[32] = "";

		if(!envname) {
			if(strcmp(name + 1, "HOST")) {
				fprintf(stderr, "Invalid Name: environment variable %s does not exist\n", name + 1);
				free(name);
				return false;
			}

			if(gethostname(hostname, sizeof(hostname)) || !*hostname) {
				fprintf(stderr, "Could not get hostname: %s\n", strerror(errno));
				free(name);
				return false;
			}

			hostname[31] = 0;
			envname = hostname;
		}

		free(name);
		name = xstrdup(envname);

		for(char *c = name; *c; c++)
			if(!isalnum(*c)) {
				*c = '_';
			}
	}

	if(!check_id(name)) {
		logger(LOG_ERR, "Invalid name for myself!");
		free(name);
		return false;
	}

	return name;
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
static bool setup_myself(void) {
	config_t *cfg;
	subnet_t *subnet;
	char *name, *hostname, *mode, *afname, *cipher, *digest, *type;
	char *fname = NULL;
	char *address = NULL;
	char *proxy = NULL;
	char *space;
	char *envp[5] = {};
	struct addrinfo *ai, *aip, hint = {};
	bool choice;
	int i, err;
	int replaywin_int;
	bool port_specified = false;

	myself = new_node();
	myself->connection = new_connection();

	myself->hostname = xstrdup("MYSELF");
	myself->connection->hostname = xstrdup("MYSELF");

	myself->connection->options = 0;
	myself->connection->protocol_version = PROT_CURRENT;

	if(!(name = get_name())) {
		logger(LOG_ERR, "Name for tinc daemon required!");
		return false;
	}

	/* Read tinc.conf and our own host config file */

	myself->name = name;
	myself->connection->name = xstrdup(name);
	xasprintf(&fname, "%s/hosts/%s", confbase, name);
	read_config_options(config_tree, name);
	read_config_file(config_tree, fname);
	free(fname);

	if(!read_rsa_private_key()) {
		return false;
	}

	if(!get_config_string(lookup_config(config_tree, "Port"), &myport)) {
		myport = xstrdup("655");
	} else {
		port_specified = true;
	}

	/* Ensure myport is numeric */

	if(!atoi(myport)) {
		struct addrinfo *ai = str2addrinfo("localhost", myport, SOCK_DGRAM);
		sockaddr_t sa;

		if(!ai || !ai->ai_addr) {
			return false;
		}

		free(myport);
		memcpy(&sa, ai->ai_addr, ai->ai_addrlen);
		sockaddr2str(&sa, NULL, &myport);
	}

	if(get_config_string(lookup_config(config_tree, "Proxy"), &proxy)) {
		if((space = strchr(proxy, ' '))) {
			*space++ = 0;
		}

		if(!strcasecmp(proxy, "none")) {
			proxytype = PROXY_NONE;
		} else if(!strcasecmp(proxy, "socks4")) {
			proxytype = PROXY_SOCKS4;
		} else if(!strcasecmp(proxy, "socks4a")) {
			proxytype = PROXY_SOCKS4A;
		} else if(!strcasecmp(proxy, "socks5")) {
			proxytype = PROXY_SOCKS5;
		} else if(!strcasecmp(proxy, "http")) {
			proxytype = PROXY_HTTP;
		} else if(!strcasecmp(proxy, "exec")) {
			proxytype = PROXY_EXEC;
		} else {
			logger(LOG_ERR, "Unknown proxy type %s!", proxy);
			free(proxy);
			return false;
		}

		switch(proxytype) {
		case PROXY_NONE:
		default:
			break;

		case PROXY_EXEC:
			if(!space || !*space) {
				logger(LOG_ERR, "Argument expected for proxy type exec!");
				free(proxy);
				return false;
			}

			proxyhost =  xstrdup(space);
			break;

		case PROXY_SOCKS4:
		case PROXY_SOCKS4A:
		case PROXY_SOCKS5:
		case PROXY_HTTP:
			proxyhost = space;

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxyport = space;
			}

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxyuser = space;
			}

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxypass = space;
			}

			if(!proxyhost || !*proxyhost || !proxyport || !*proxyport) {
				logger(LOG_ERR, "Host and port argument expected for proxy!");
				free(proxy);
				return false;
			}

			proxyhost = xstrdup(proxyhost);
			proxyport = xstrdup(proxyport);

			if(proxyuser && *proxyuser) {
				proxyuser = xstrdup(proxyuser);
			}

			if(proxypass && *proxypass) {
				proxypass = xstrdup(proxypass);
			}

			break;
		}

		free(proxy);
	}

	/* Read in all the subnets specified in the host configuration file */

	cfg = lookup_config(config_tree, "Subnet");

	while(cfg) {
		if(!get_config_subnet(cfg, &subnet)) {
			return false;
		}

		subnet_add(myself, subnet);

		cfg = lookup_config_next(config_tree, cfg);
	}

	/* Check some options */

	if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice) && choice) {
		myself->options |= OPTION_INDIRECT;
	}

	if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice) && choice) {
		myself->options |= OPTION_TCPONLY;
	}

	if(myself->options & OPTION_TCPONLY) {
		myself->options |= OPTION_INDIRECT;
	}

	get_config_bool(lookup_config(config_tree, "DirectOnly"), &directonly);
	get_config_bool(lookup_config(config_tree, "StrictSubnets"), &strictsubnets);
	get_config_bool(lookup_config(config_tree, "TunnelServer"), &tunnelserver);
	get_config_bool(lookup_config(config_tree, "LocalDiscovery"), &localdiscovery);
	strictsubnets |= tunnelserver;

	if(get_config_string(lookup_config(config_tree, "Mode"), &mode)) {
		if(!strcasecmp(mode, "router")) {
			routing_mode = RMODE_ROUTER;
		} else if(!strcasecmp(mode, "switch")) {
			routing_mode = RMODE_SWITCH;
		} else if(!strcasecmp(mode, "hub")) {
			routing_mode = RMODE_HUB;
		} else {
			logger(LOG_ERR, "Invalid routing mode!");
			free(mode);
			return false;
		}

		free(mode);
	}

	if(get_config_string(lookup_config(config_tree, "Forwarding"), &mode)) {
		if(!strcasecmp(mode, "off")) {
			forwarding_mode = FMODE_OFF;
		} else if(!strcasecmp(mode, "internal")) {
			forwarding_mode = FMODE_INTERNAL;
		} else if(!strcasecmp(mode, "kernel")) {
			forwarding_mode = FMODE_KERNEL;
		} else {
			logger(LOG_ERR, "Invalid forwarding mode!");
			free(mode);
			return false;
		}

		free(mode);
	}

	choice = !(myself->options & OPTION_TCPONLY);
	get_config_bool(lookup_config(config_tree, "PMTUDiscovery"), &choice);

	if(choice) {
		myself->options |= OPTION_PMTU_DISCOVERY;
	}

	choice = true;
	get_config_bool(lookup_config(config_tree, "ClampMSS"), &choice);

	if(choice) {
		myself->options |= OPTION_CLAMP_MSS;
	}

	get_config_bool(lookup_config(config_tree, "PriorityInheritance"), &priorityinheritance);
	get_config_bool(lookup_config(config_tree, "DecrementTTL"), &decrement_ttl);

	if(get_config_string(lookup_config(config_tree, "Broadcast"), &mode)) {
		if(!strcasecmp(mode, "no")) {
			broadcast_mode = BMODE_NONE;
		} else if(!strcasecmp(mode, "yes") || !strcasecmp(mode, "mst")) {
			broadcast_mode = BMODE_MST;
		} else if(!strcasecmp(mode, "direct")) {
			broadcast_mode = BMODE_DIRECT;
		} else {
			logger(LOG_ERR, "Invalid broadcast mode!");
			free(mode);
			return false;
		}

		free(mode);
	}

#if !defined(SOL_IP) || !defined(IP_TOS)

	if(priorityinheritance) {
		logger(LOG_WARNING, "%s not supported on this platform for IPv4 connection", "PriorityInheritance");
	}

#endif

#if !defined(IPPROTO_IPV6) || !defined(IPV6_TCLASS)

	if(priorityinheritance) {
		logger(LOG_WARNING, "%s not supported on this platform for IPv6 connection", "PriorityInheritance");
	}

#endif

	if(!get_config_int(lookup_config(config_tree, "MACExpire"), &macexpire)) {
		macexpire = 600;
	}

	if(get_config_int(lookup_config(config_tree, "MaxTimeout"), &maxtimeout)) {
		if(maxtimeout <= 0) {
			logger(LOG_ERR, "Bogus maximum timeout!");
			return false;
		}
	} else {
		maxtimeout = 900;
	}

	if(get_config_int(lookup_config(config_tree, "MinTimeout"), &mintimeout)) {
		if(mintimeout < 0) {
			logger(LOG_ERR, "Bogus minimum timeout!");
			return false;
		}

		if(mintimeout > maxtimeout) {
			logger(LOG_WARNING, "Minimum timeout (%d s) cannot be larger than maximum timeout (%d s). Correcting !", mintimeout, maxtimeout);
			mintimeout = maxtimeout;
		}
	} else {
		mintimeout = 0;
	}

	if(get_config_int(lookup_config(config_tree, "UDPRcvBuf"), &udp_rcvbuf)) {
		if(udp_rcvbuf <= 0) {
			logger(LOG_ERR, "UDPRcvBuf cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(config_tree, "UDPSndBuf"), &udp_sndbuf)) {
		if(udp_sndbuf <= 0) {
			logger(LOG_ERR, "UDPSndBuf cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(config_tree, "ReplayWindow"), &replaywin_int)) {
		if(replaywin_int < 0) {
			logger(LOG_ERR, "ReplayWindow cannot be negative!");
			return false;
		}

		replaywin = (unsigned)replaywin_int;
	}

	if(get_config_string(lookup_config(config_tree, "AddressFamily"), &afname)) {
		if(!strcasecmp(afname, "IPv4")) {
			addressfamily = AF_INET;
		} else if(!strcasecmp(afname, "IPv6")) {
			addressfamily = AF_INET6;
		} else if(!strcasecmp(afname, "any")) {
			addressfamily = AF_UNSPEC;
		} else {
			logger(LOG_ERR, "Invalid address family!");
			free(afname);
			return false;
		}

		free(afname);
	}

	get_config_bool(lookup_config(config_tree, "Hostnames"), &hostnames);

	/* Generate packet encryption key */

	if(get_config_string(lookup_config(config_tree, "Cipher"), &cipher)) {
		if(!strcasecmp(cipher, "none")) {
			myself->incipher = NULL;
		} else {
			myself->incipher = EVP_get_cipherbyname(cipher);

			if(!myself->incipher) {
				logger(LOG_ERR, "Unrecognized cipher type!");
				free(cipher);
				return false;
			}
		}

		free(cipher);
	} else {
		myself->incipher = EVP_aes_256_cbc();
	}

	if(myself->incipher) {
		myself->inkeylength = EVP_CIPHER_key_length(myself->incipher) + EVP_CIPHER_iv_length(myself->incipher);
	} else {
		myself->inkeylength = 1;
	}

	/* We need to use a stream mode for the meta protocol. Use AES for this,
	   but try to match the key size with the one from the cipher selected
	   by Cipher.

	   If Cipher is set to none, still use a low level of encryption for the
	   meta protocol.
	*/

	int keylen = myself->incipher ? EVP_CIPHER_key_length(myself->incipher) : 0;

	if(keylen <= 16) {
		myself->connection->outcipher = EVP_aes_128_cfb();
	} else if(keylen <= 24) {
		myself->connection->outcipher = EVP_aes_192_cfb();
	} else {
		myself->connection->outcipher = EVP_aes_256_cfb();
	}

	if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime)) {
		keylifetime = 3600;
	}

	keyexpires = now + keylifetime;

	/* Check if we want to use message authentication codes... */

	if(get_config_string(lookup_config(config_tree, "Digest"), &digest)) {
		if(!strcasecmp(digest, "none")) {
			myself->indigest = NULL;
		} else {
			myself->indigest = EVP_get_digestbyname(digest);

			if(!myself->indigest) {
				logger(LOG_ERR, "Unrecognized digest type!");
				free(digest);
				return false;
			}
		}

		free(digest);
	} else {
		myself->indigest = EVP_sha256();
	}

	myself->connection->outdigest = EVP_sha256();

	if(get_config_int(lookup_config(config_tree, "MACLength"), &myself->inmaclength)) {
		if(myself->indigest) {
			if(myself->inmaclength > EVP_MD_size(myself->indigest)) {
				logger(LOG_ERR, "MAC length exceeds size of digest!");
				return false;
			} else if(myself->inmaclength < 0) {
				logger(LOG_ERR, "Bogus MAC length!");
				return false;
			}
		}
	} else {
		myself->inmaclength = 4;
	}

	myself->connection->outmaclength = 0;

	/* Compression */

	if(get_config_int(lookup_config(config_tree, "Compression"), &myself->incompression)) {
		if(myself->incompression < 0 || myself->incompression > 11) {
			logger(LOG_ERR, "Bogus compression level!");
			return false;
		}
	} else {
		myself->incompression = 0;
	}

	myself->connection->outcompression = 0;

	/* Done */

	myself->nexthop = myself;
	myself->via = myself;
	myself->status.reachable = true;
	node_add(myself);

	graph();

	if(strictsubnets) {
		load_all_subnets();
	}

	/* Open device */

	devops = os_devops;

	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "dummy")) {
			devops = dummy_devops;
		} else if(!strcasecmp(type, "raw_socket")) {
			devops = raw_socket_devops;
		} else if(!strcasecmp(type, "multicast")) {
			devops = multicast_devops;
		}

#ifdef ENABLE_UML
		else if(!strcasecmp(type, "uml")) {
			devops = uml_devops;
		}

#endif
#ifdef ENABLE_VDE
		else if(!strcasecmp(type, "vde")) {
			devops = vde_devops;
		}

#endif
		free(type);
	}

	if(!devops.setup()) {
		return false;
	}

	/* Run tinc-up script to further initialize the tap interface */
	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myself->name);

#ifdef HAVE_MINGW
	Sleep(1000);
#endif
#ifdef HAVE_CYGWIN
	sleep(1);
#endif
	execute_script("tinc-up", envp);

	for(i = 0; i < 4; i++) {
		free(envp[i]);
	}

	/* Run subnet-up scripts for our own subnets */

	subnet_update(myself, NULL, true);

	/* Open sockets */

	if(!do_detach && getenv("LISTEN_FDS")) {
		sockaddr_t sa;
		socklen_t salen;

		listen_sockets = atoi(getenv("LISTEN_FDS"));
#ifdef HAVE_UNSETENV
		unsetenv("LISTEN_FDS");
#endif

		if(listen_sockets > MAXSOCKETS) {
			logger(LOG_ERR, "Too many listening sockets");
			return false;
		}

		for(i = 0; i < listen_sockets; i++) {
			salen = sizeof(sa);

			if(getsockname(i + 3, &sa.sa, &salen) < 0) {
				logger(LOG_ERR, "Could not get address of listen fd %d: %s", i + 3, sockstrerror(errno));
				return false;
			}

			listen_socket[i].tcp = i + 3;

#ifdef FD_CLOEXEC
			fcntl(i + 3, F_SETFD, FD_CLOEXEC);
#endif

			listen_socket[i].udp = setup_vpn_in_socket(&sa);

			if(listen_socket[i].udp < 0) {
				return false;
			}

			ifdebug(CONNECTIONS) {
				hostname = sockaddr2hostname(&sa);
				logger(LOG_NOTICE, "Listening on %s", hostname);
				free(hostname);
			}

			memcpy(&listen_socket[i].sa, &sa, salen);
		}
	} else {
		listen_sockets = 0;
		cfg = lookup_config(config_tree, "BindToAddress");

		do {
			get_config_string(cfg, &address);

			if(cfg) {
				cfg = lookup_config_next(config_tree, cfg);
			}

			char *port = myport;

			if(address) {
				char *space = strchr(address, ' ');

				if(space) {
					*space++ = 0;
					port = space;
				}

				if(!strcmp(address, "*")) {
					*address = 0;
				}
			}

			hint.ai_family = addressfamily;
			hint.ai_socktype = SOCK_STREAM;
			hint.ai_protocol = IPPROTO_TCP;
			hint.ai_flags = AI_PASSIVE;

#if HAVE_DECL_RES_INIT
			// ensure glibc reloads /etc/resolv.conf.
			res_init();
#endif
			err = getaddrinfo(address && *address ? address : NULL, port, &hint, &ai);
			free(address);

			if(err || !ai) {
				logger(LOG_ERR, "System call `%s' failed: %s", "getaddrinfo",
				       gai_strerror(err));
				return false;
			}

			for(aip = ai; aip; aip = aip->ai_next) {
				if(listen_sockets >= MAXSOCKETS) {
					logger(LOG_ERR, "Too many listening sockets");
					return false;
				}

				listen_socket[listen_sockets].tcp =
				        setup_listen_socket((sockaddr_t *) aip->ai_addr);

				if(listen_socket[listen_sockets].tcp < 0) {
					continue;
				}

				listen_socket[listen_sockets].udp =
				        setup_vpn_in_socket((sockaddr_t *) aip->ai_addr);

				if(listen_socket[listen_sockets].udp < 0) {
					continue;
				}

				ifdebug(CONNECTIONS) {
					hostname = sockaddr2hostname((sockaddr_t *) aip->ai_addr);
					logger(LOG_NOTICE, "Listening on %s", hostname);
					free(hostname);
				}

				memcpy(&listen_socket[listen_sockets].sa, aip->ai_addr, aip->ai_addrlen);
				listen_sockets++;
			}

			freeaddrinfo(ai);
		} while(cfg);
	}

	if(!listen_sockets) {
		logger(LOG_ERR, "Unable to create any listening socket!");
		return false;
	}

	/* If no Port option was specified, set myport to the port used by the first listening socket. */

	if(!port_specified) {
		sockaddr_t sa;
		socklen_t salen = sizeof(sa);

		if(!getsockname(listen_socket[0].udp, &sa.sa, &salen)) {
			free(myport);
			sockaddr2str(&sa, NULL, &myport);

			if(!myport) {
				myport = xstrdup("655");
			}
		}
	}

	/* Done. */

	logger(LOG_NOTICE, "Ready");
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
	} else {
		pinginterval = 60;
	}

	if(!get_config_int(lookup_config(config_tree, "PingTimeout"), &pingtimeout)) {
		pingtimeout = 5;
	}

	if(pingtimeout < 1 || pingtimeout > pinginterval) {
		pingtimeout = pinginterval;
	}

	if(!get_config_int(lookup_config(config_tree, "MaxOutputBufferSize"), &maxoutbufsize)) {
		maxoutbufsize = 10 * MTU;
	}

	if(!setup_myself()) {
		return false;
	}

	return true;
}

/*
  close all open network connections
*/
void close_network_connections(void) {
	avl_node_t *node, *next;
	connection_t *c;
	char *envp[5] = {};
	int i;

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;
		c->outgoing = NULL;
		terminate_connection(c, false);
	}

	for(list_node_t *node = outgoing_list->head; node; node = node->next) {
		outgoing_t *outgoing = node->data;

		if(outgoing->event) {
			event_del(outgoing->event);
		}
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

	exit_requests();
	exit_edges();
	exit_subnets();
	exit_nodes();
	exit_connections();
	exit_events();

	execute_script("tinc-down", envp);

	if(myport) {
		free(myport);
	}

	for(i = 0; i < 4; i++) {
		free(envp[i]);
	}

	devops.close();

	return;
}
