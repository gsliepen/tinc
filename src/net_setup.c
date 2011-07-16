/*
    net_setup.c -- Setup.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2010 Guus Sliepen <guus@tinc-vpn.org>
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

#include "splay_tree.h"
#include "cipher.h"
#include "conf.h"
#include "connection.h"
#include "control.h"
#include "device.h"
#include "digest.h"
#include "ecdsa.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "route.h"
#include "rsa.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

char *myport;
static struct event device_ev;

bool node_read_ecdsa_public_key(node_t *n) {
	if(ecdsa_active(&n->ecdsa))
		return true;

	splay_tree_t *config_tree;
	FILE *fp;
	char *fname;
	char *p;
	bool result = false;

	xasprintf(&fname, "%s/hosts/%s", confbase, n->name);

	init_configuration(&config_tree);
	if(!read_config_file(config_tree, fname))
		goto exit;

	/* First, check for simple ECDSAPublicKey statement */

	if(get_config_string(lookup_config(config_tree, "ECDSAPublicKey"), &p)) {
		result = ecdsa_set_base64_public_key(&n->ecdsa, p);
		free(p);
		goto exit;
	}

	/* Else, check for ECDSAPublicKeyFile statement and read it */

	free(fname);

	if(!get_config_string(lookup_config(config_tree, "ECDSAPublicKeyFile"), &fname))
		xasprintf(&fname, "%s/hosts/%s", confbase, n->name);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading ECDSA public key file `%s': %s", fname, strerror(errno));
		goto exit;
	}

	result = ecdsa_read_pem_public_key(&n->ecdsa, fp);
	fclose(fp);

exit:
	exit_configuration(&config_tree);
	free(fname);
	return result;
}

bool read_ecdsa_public_key(connection_t *c) {
	FILE *fp;
	char *fname;
	char *p;
	bool result;

	/* First, check for simple ECDSAPublicKey statement */

	if(get_config_string(lookup_config(c->config_tree, "ECDSAPublicKey"), &p)) {
		result = ecdsa_set_base64_public_key(&c->ecdsa, p);
		free(p);
		return result;
	}

	/* Else, check for ECDSAPublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(c->config_tree, "ECDSAPublicKeyFile"), &fname))
		xasprintf(&fname, "%s/hosts/%s", confbase, c->name);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading ECDSA public key file `%s': %s",
			   fname, strerror(errno));
		free(fname);
		return false;
	}

	result = ecdsa_read_pem_public_key(&c->ecdsa, fp);
	fclose(fp);

	if(!result) 
		logger(LOG_ERR, "Reading ECDSA public key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return result;
}

bool read_rsa_public_key(connection_t *c) {
	FILE *fp;
	char *fname;
	char *n;
	bool result;

	/* First, check for simple PublicKey statement */

	if(get_config_string(lookup_config(c->config_tree, "PublicKey"), &n)) {
		result = rsa_set_hex_public_key(&c->rsa, n, "FFFF");
		free(n);
		return result;
	}

	/* Else, check for PublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(c->config_tree, "PublicKeyFile"), &fname))
		xasprintf(&fname, "%s/hosts/%s", confbase, c->name);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading RSA public key file `%s': %s",
			   fname, strerror(errno));
		free(fname);
		return false;
	}

	result = rsa_read_pem_public_key(&c->rsa, fp);
	fclose(fp);

	if(!result) 
		logger(LOG_ERR, "Reading RSA public key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return result;
}

static bool read_ecdsa_private_key(void) {
	FILE *fp;
	char *fname;
	bool result;

	/* Check for PrivateKeyFile statement and read it */

	if(!get_config_string(lookup_config(config_tree, "ECDSAPrivateKeyFile"), &fname))
		xasprintf(&fname, "%s/ecdsa_key.priv", confbase);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, "Error reading ECDSA private key file `%s': %s",
			   fname, strerror(errno));
		free(fname);
		return false;
	}

#if !defined(HAVE_MINGW) && !defined(HAVE_CYGWIN)
	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(LOG_ERR, "Could not stat ECDSA private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		return false;
	}

	if(s.st_mode & ~0100700)
		logger(LOG_WARNING, "Warning: insecure file permissions for ECDSA private key file `%s'!", fname);
#endif

	result = ecdsa_read_pem_private_key(&myself->connection->ecdsa, fp);
	fclose(fp);

	if(!result) 
		logger(LOG_ERR, "Reading ECDSA private key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return result;
}

static bool read_rsa_private_key(void) {
	FILE *fp;
	char *fname;
	char *n, *d;
	bool result;

	/* First, check for simple PrivateKey statement */

	if(get_config_string(lookup_config(config_tree, "PrivateKey"), &d)) {
		if(!get_config_string(lookup_config(config_tree, "PublicKey"), &n)) {
			logger(LOG_ERR, "PrivateKey used but no PublicKey found!");
			free(d);
			return false;
		}
		result = rsa_set_hex_private_key(&myself->connection->rsa, n, "FFFF", d);
		free(n);
		free(d);
		return true;
	}

	/* Else, check for PrivateKeyFile statement and read it */

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
	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(LOG_ERR, "Could not stat RSA private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		return false;
	}

	if(s.st_mode & ~0100700)
		logger(LOG_WARNING, "Warning: insecure file permissions for RSA private key file `%s'!", fname);
#endif

	result = rsa_read_pem_private_key(&myself->connection->rsa, fp);
	fclose(fp);

	if(!result) 
		logger(LOG_ERR, "Reading RSA private key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return result;
}

static struct event keyexpire_event;

static void keyexpire_handler(int fd, short events, void *data) {
	regenerate_key();
}

void regenerate_key(void) {
	if(timeout_initialized(&keyexpire_event)) {
		ifdebug(STATUS) logger(LOG_INFO, "Expiring symmetric keys");
		event_del(&keyexpire_event);
		send_key_changed();
	} else {
		timeout_set(&keyexpire_event, keyexpire_handler, NULL);
	}

	event_add(&keyexpire_event, &(struct timeval){keylifetime, 0});
}

/*
  Read Subnets from all host config files
*/
void load_all_subnets(void) {
	DIR *dir;
	struct dirent *ent;
	char *dname;
	char *fname;
	splay_tree_t *config_tree;
	config_t *cfg;
	subnet_t *s, *s2;
	node_t *n;
	bool result;

	xasprintf(&dname, "%s/hosts", confbase);
	dir = opendir(dname);
	if(!dir) {
		logger(LOG_ERR, "Could not open %s: %s", dname, strerror(errno));
		free(dname);
		return;
	}

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		n = lookup_node(ent->d_name);
		#ifdef _DIRENT_HAVE_D_TYPE
		//if(ent->d_type != DT_REG)
		//	continue;
		#endif

		xasprintf(&fname, "%s/hosts/%s", confbase, ent->d_name);
		init_configuration(&config_tree);
		result = read_config_file(config_tree, fname);
		free(fname);
		if(!result)
			continue;

		if(!n) {
			n = new_node();
			n->name = xstrdup(ent->d_name);
			node_add(n);
		}

		for(cfg = lookup_config(config_tree, "Subnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			if(!get_config_subnet(cfg, &s))
				continue;

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

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
static bool setup_myself(void) {
	config_t *cfg;
	subnet_t *subnet;
	char *name, *hostname, *mode, *afname, *cipher, *digest;
	char *fname = NULL;
	char *address = NULL;
	char *envp[5];
	struct addrinfo *ai, *aip, hint = {0};
	bool choice;
	int i, err;
	int replaywin_int;

	myself = new_node();
	myself->connection = new_connection();

	myself->hostname = xstrdup("MYSELF");
	myself->connection->hostname = xstrdup("MYSELF");

	myself->connection->options = 0;
	myself->connection->protocol_major = PROT_MAJOR;
	myself->connection->protocol_minor = PROT_MINOR;

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
	xasprintf(&fname, "%s/hosts/%s", confbase, name);
	read_config_options(config_tree, name);
	read_config_file(config_tree, fname);
	free(fname);

	get_config_bool(lookup_config(config_tree, "ExperimentalProtocol"), &experimental);

	if(experimental && !read_ecdsa_private_key())
		return false;

	if(!read_rsa_private_key())
		return false;

	if(!get_config_string(lookup_config(config_tree, "Port"), &myport))
		myport = xstrdup("655");

	if(!atoi(myport)) {
		struct addrinfo *ai = str2addrinfo("localhost", myport, SOCK_DGRAM);
		sockaddr_t sa;
		if(!ai || !ai->ai_addr)
			return false;
		free(myport);
		memcpy(&sa, ai->ai_addr, ai->ai_addrlen);
		sockaddr2str(&sa, NULL, &myport);
	}

	/* Read in all the subnets specified in the host configuration file */

	cfg = lookup_config(config_tree, "Subnet");

	while(cfg) {
		if(!get_config_subnet(cfg, &subnet))
			return false;

		subnet_add(myself, subnet);

		cfg = lookup_config_next(config_tree, cfg);
	}

	/* Check some options */

	if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice) && choice)
		myself->options |= OPTION_INDIRECT;

	if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice) && choice)
		myself->options |= OPTION_TCPONLY;

	if(myself->options & OPTION_TCPONLY)
		myself->options |= OPTION_INDIRECT;

	get_config_bool(lookup_config(config_tree, "DirectOnly"), &directonly);
	get_config_bool(lookup_config(config_tree, "StrictSubnets"), &strictsubnets);
	get_config_bool(lookup_config(config_tree, "TunnelServer"), &tunnelserver);
	strictsubnets |= tunnelserver;

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
	}

	if(get_config_string(lookup_config(config_tree, "Forwarding"), &mode)) {
		if(!strcasecmp(mode, "off"))
			forwarding_mode = FMODE_OFF;
		else if(!strcasecmp(mode, "internal"))
			forwarding_mode = FMODE_INTERNAL;
		else if(!strcasecmp(mode, "kernel"))
			forwarding_mode = FMODE_KERNEL;
		else {
			logger(LOG_ERR, "Invalid forwarding mode!");
			return false;
		}
		free(mode);
	}

	choice = true;
	get_config_bool(lookup_config(config_tree, "PMTUDiscovery"), &choice);
	if(choice)
		myself->options |= OPTION_PMTU_DISCOVERY;

	choice = true;
	get_config_bool(lookup_config(config_tree, "ClampMSS"), &choice);
	if(choice)
		myself->options |= OPTION_CLAMP_MSS;

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

	if(!get_config_string(lookup_config(config_tree, "Cipher"), &cipher))
		cipher = xstrdup("blowfish");

	if(!cipher_open_by_name(&myself->incipher, cipher)) {
		logger(LOG_ERR, "Unrecognized cipher type!");
		return false;
	}

	if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime))
		keylifetime = 3600;

	regenerate_key();

	/* Check if we want to use message authentication codes... */

	if(!get_config_string(lookup_config(config_tree, "Digest"), &digest))
		digest = xstrdup("sha1");

	int maclength = 4;
	get_config_int(lookup_config(config_tree, "MACLength"), &maclength);

	if(maclength < 0) {
		logger(LOG_ERR, "Bogus MAC length!");
		return false;
	}

	if(!digest_open_by_name(&myself->indigest, digest, maclength)) {
		logger(LOG_ERR, "Unrecognized digest type!");
		return false;
	}

	/* Compression */

	if(get_config_int(lookup_config(config_tree, "Compression"), &myself->incompression)) {
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

	if(strictsubnets)
		load_all_subnets();

	/* Open device */

	if(!setup_device())
		return false;

	if(device_fd >= 0) {
		event_set(&device_ev, device_fd, EV_READ|EV_PERSIST, handle_device_data, NULL);

		if (event_add(&device_ev, NULL) < 0) {
			logger(LOG_ERR, "event_add failed: %s", strerror(errno));
			close_device();
			return false;
		}
	}

	/* Run tinc-up script to further initialize the tap interface */
	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	execute_script("tinc-up", envp);

	for(i = 0; i < 4; i++)
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

		if(listen_socket[listen_sockets].udp < 0) {
			close(listen_socket[listen_sockets].tcp);
			continue;
		}

		event_set(&listen_socket[listen_sockets].ev_tcp,
				  listen_socket[listen_sockets].tcp,
				  EV_READ|EV_PERSIST,
				  handle_new_meta_connection, NULL);
		if(event_add(&listen_socket[listen_sockets].ev_tcp, NULL) < 0) {
			logger(LOG_ERR, "event_add failed: %s", strerror(errno));
			abort();
		}

		event_set(&listen_socket[listen_sockets].ev_udp,
				  listen_socket[listen_sockets].udp,
				  EV_READ|EV_PERSIST,
				  handle_incoming_vpn_data, NULL);
		if(event_add(&listen_socket[listen_sockets].ev_udp, NULL) < 0) {
			logger(LOG_ERR, "event_add failed: %s", strerror(errno));
			abort();
		}

		ifdebug(CONNECTIONS) {
			hostname = sockaddr2hostname((sockaddr_t *) aip->ai_addr);
			logger(LOG_NOTICE, "Listening on %s", hostname);
			free(hostname);
		}

		memcpy(&listen_socket[listen_sockets].sa, aip->ai_addr, aip->ai_addrlen);
		listen_sockets++;

		if(listen_sockets >= MAXSOCKETS) {
			logger(LOG_WARNING, "Maximum of %d listening sockets reached", MAXSOCKETS);
			break;
		}
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
	splay_node_t *node, *next;
	connection_t *c;
	char *envp[5];
	int i;

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;
		c->outgoing = NULL;
		terminate_connection(c, false);
	}

	list_delete_list(outgoing_list);

	if(myself && myself->connection) {
		subnet_update(myself, NULL, false);
		terminate_connection(myself->connection, false);
		free_connection(myself->connection);
	}

	for(i = 0; i < listen_sockets; i++) {
		event_del(&listen_socket[i].ev_tcp);
		event_del(&listen_socket[i].ev_udp);
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

	execute_script("tinc-down", envp);

	if(myport) free(myport);

	for(i = 0; i < 4; i++)
		free(envp[i]);

	close_device();

	return;
}
