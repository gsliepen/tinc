/*
    net_setup.c -- Setup.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>
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

#include "cipher.h"
#include "conf.h"
#include "connection.h"
#include "control.h"
#include "device.h"
#include "digest.h"
#include "ecdsa.h"
#include "graph.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "route.h"
#include "rsa.h"
#include "script.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

char *myport;
static char *myname;
static io_t device_io;
devops_t devops;
bool device_standby = false;

char *proxyhost;
char *proxyport;
char *proxyuser;
char *proxypass;
proxytype_t proxytype;
bool autoconnect;
bool disablebuggypeers;

char *scriptinterpreter;
char *scriptextension;

bool node_read_ecdsa_public_key(node_t *n) {
	if(ecdsa_active(n->ecdsa))
		return true;

	splay_tree_t *config_tree;
	FILE *fp;
	char *pubname = NULL;
	char *p;

	init_configuration(&config_tree);
	if(!read_host_config(config_tree, n->name))
		goto exit;

	/* First, check for simple Ed25519PublicKey statement */

	if(get_config_string(lookup_config(config_tree, "Ed25519PublicKey"), &p)) {
		n->ecdsa = ecdsa_set_base64_public_key(p);
		free(p);
		goto exit;
	}

	/* Else, check for Ed25519PublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(config_tree, "Ed25519PublicKeyFile"), &pubname))
		xasprintf(&pubname, "%s" SLASH "hosts" SLASH "%s", confbase, n->name);

	fp = fopen(pubname, "r");

	if(!fp)
		goto exit;

	n->ecdsa = ecdsa_read_pem_public_key(fp);
	fclose(fp);

exit:
	exit_configuration(&config_tree);
	free(pubname);
	return n->ecdsa;
}

bool read_ecdsa_public_key(connection_t *c) {
	if(ecdsa_active(c->ecdsa))
		return true;

	FILE *fp;
	char *fname;
	char *p;

	if(!c->config_tree) {
		init_configuration(&c->config_tree);
		if(!read_host_config(c->config_tree, c->name))
			return false;
	}

	/* First, check for simple Ed25519PublicKey statement */

	if(get_config_string(lookup_config(c->config_tree, "Ed25519PublicKey"), &p)) {
		c->ecdsa = ecdsa_set_base64_public_key(p);
		free(p);
		return c->ecdsa;
	}

	/* Else, check for Ed25519PublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(c->config_tree, "Ed25519PublicKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, c->name);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading Ed25519 public key file `%s': %s",
			   fname, strerror(errno));
		free(fname);
		return false;
	}

	c->ecdsa = ecdsa_read_pem_public_key(fp);
	fclose(fp);

	if(!c->ecdsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Parsing Ed25519 public key file `%s' failed.", fname);
	free(fname);
	return c->ecdsa;
}

bool read_rsa_public_key(connection_t *c) {
	if(ecdsa_active(c->ecdsa))
		return true;

	FILE *fp;
	char *fname;
	char *n;

	/* First, check for simple PublicKey statement */

	if(get_config_string(lookup_config(c->config_tree, "PublicKey"), &n)) {
		c->rsa = rsa_set_hex_public_key(n, "FFFF");
		free(n);
		return c->rsa;
	}

	/* Else, check for PublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(c->config_tree, "PublicKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, c->name);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading RSA public key file `%s': %s", fname, strerror(errno));
		free(fname);
		return false;
	}

	c->rsa = rsa_read_pem_public_key(fp);
	fclose(fp);

	if(!c->rsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading RSA public key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return c->rsa;
}

static bool read_ecdsa_private_key(void) {
	FILE *fp;
	char *fname;

	/* Check for PrivateKeyFile statement and read it */

	if(!get_config_string(lookup_config(config_tree, "Ed25519PrivateKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "ed25519_key.priv", confbase);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading Ed25519 private key file `%s': %s", fname, strerror(errno));
		if(errno == ENOENT)
			logger(DEBUG_ALWAYS, LOG_INFO, "Create an Ed25519 keypair with `tinc -n %s generate-ed25519-keys'.", netname ?: ".");
		free(fname);
		return false;
	}

#if !defined(HAVE_MINGW) && !defined(HAVE_CYGWIN)
	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat Ed25519 private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		return false;
	}

	if(s.st_mode & ~0100700)
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: insecure file permissions for Ed25519 private key file `%s'!", fname);
#endif

	myself->connection->ecdsa = ecdsa_read_pem_private_key(fp);
	fclose(fp);

	if(!myself->connection->ecdsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading Ed25519 private key file `%s' failed", fname);
	free(fname);
	return myself->connection->ecdsa;
}

static bool read_invitation_key(void) {
	FILE *fp;
	char *fname;

	if(invitation_key) {
		ecdsa_free(invitation_key);
		invitation_key = NULL;
	}

	xasprintf(&fname, "%s" SLASH "invitations" SLASH "ed25519_key.priv", confbase);

	fp = fopen(fname, "r");

	if(fp) {
		invitation_key = ecdsa_read_pem_private_key(fp);
		fclose(fp);
		if(!invitation_key)
			logger(DEBUG_ALWAYS, LOG_ERR, "Reading Ed25519 private key file `%s' failed", fname);
	}

	free(fname);
	return invitation_key;
}

static bool read_rsa_private_key(void) {
	FILE *fp;
	char *fname;
	char *n, *d;

	/* First, check for simple PrivateKey statement */

	if(get_config_string(lookup_config(config_tree, "PrivateKey"), &d)) {
		if(!get_config_string(lookup_config(config_tree, "PublicKey"), &n)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "PrivateKey used but no PublicKey found!");
			free(d);
			return false;
		}
		myself->connection->rsa = rsa_set_hex_private_key(n, "FFFF", d);
		free(n);
		free(d);
		return myself->connection->rsa;
	}

	/* Else, check for PrivateKeyFile statement and read it */

	if(!get_config_string(lookup_config(config_tree, "PrivateKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "rsa_key.priv", confbase);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading RSA private key file `%s': %s",
			   fname, strerror(errno));
		if(errno == ENOENT)
			logger(DEBUG_ALWAYS, LOG_INFO, "Create an RSA keypair with `tinc -n %s generate-rsa-keys'.", netname ?: ".");
		free(fname);
		return false;
	}

#if !defined(HAVE_MINGW) && !defined(HAVE_CYGWIN)
	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat RSA private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		return false;
	}

	if(s.st_mode & ~0100700)
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: insecure file permissions for RSA private key file `%s'!", fname);
#endif

	myself->connection->rsa = rsa_read_pem_private_key(fp);
	fclose(fp);

	if(!myself->connection->rsa)
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading RSA private key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return myself->connection->rsa;
}

static timeout_t keyexpire_timeout;

static void keyexpire_handler(void *data) {
	regenerate_key();
	timeout_set(data, &(struct timeval){keylifetime, rand() % 100000});
}

void regenerate_key(void) {
	logger(DEBUG_STATUS, LOG_INFO, "Expiring symmetric keys");
	send_key_changed();
}

/*
  Read Subnets from all host config files
*/
void load_all_subnets(void) {
	DIR *dir;
	struct dirent *ent;
	char *dname;

	xasprintf(&dname, "%s" SLASH "hosts", confbase);
	dir = opendir(dname);
	if(!dir) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", dname, strerror(errno));
		free(dname);
		return;
	}

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		node_t *n = lookup_node(ent->d_name);
		#ifdef _DIRENT_HAVE_D_TYPE
		//if(ent->d_type != DT_REG)
		//	continue;
		#endif

		splay_tree_t *config_tree;
		init_configuration(&config_tree);
		read_config_options(config_tree, ent->d_name);
		read_host_config(config_tree, ent->d_name);

		if(!n) {
			n = new_node();
			n->name = xstrdup(ent->d_name);
			node_add(n);
		}

		for(config_t *cfg = lookup_config(config_tree, "Subnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			subnet_t *s, *s2;

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

void load_all_nodes(void) {
	DIR *dir;
	struct dirent *ent;
	char *dname;

	xasprintf(&dname, "%s" SLASH "hosts", confbase);
	dir = opendir(dname);
	if(!dir) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", dname, strerror(errno));
		free(dname);
		return;
	}

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		node_t *n = lookup_node(ent->d_name);
		if(n)
			continue;

		n = new_node();
		n->name = xstrdup(ent->d_name);
		node_add(n);
	}

	closedir(dir);
}


char *get_name(void) {
	char *name = NULL;
	char *returned_name;

	get_config_string(lookup_config(config_tree, "Name"), &name);

	if(!name)
		return NULL;

	returned_name = replace_name(name);
	free(name);
	return returned_name;
}

bool setup_myself_reloadable(void) {
	char *proxy = NULL;
	char *rmode = NULL;
	char *fmode = NULL;
	char *bmode = NULL;
	char *afname = NULL;
	char *space;
	bool choice;

	free(scriptinterpreter);
	scriptinterpreter = NULL;
	get_config_string(lookup_config(config_tree, "ScriptsInterpreter"), &scriptinterpreter);


	free(scriptextension);
	if(!get_config_string(lookup_config(config_tree, "ScriptsExtension"), &scriptextension))
		scriptextension = xstrdup("");

	get_config_string(lookup_config(config_tree, "Proxy"), &proxy);
	if(proxy) {
		if((space = strchr(proxy, ' ')))
			*space++ = 0;

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
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type %s!", proxy);
			return false;
		}

		switch(proxytype) {
			case PROXY_NONE:
			default:
				break;

			case PROXY_EXEC:
				if(!space || !*space) {
					logger(DEBUG_ALWAYS, LOG_ERR, "Argument expected for proxy type exec!");
					return false;
				}
				proxyhost =  xstrdup(space);
				break;

			case PROXY_SOCKS4:
			case PROXY_SOCKS4A:
			case PROXY_SOCKS5:
			case PROXY_HTTP:
				proxyhost = space;
				if(space && (space = strchr(space, ' ')))
					*space++ = 0, proxyport = space;
				if(space && (space = strchr(space, ' ')))
					*space++ = 0, proxyuser = space;
				if(space && (space = strchr(space, ' ')))
					*space++ = 0, proxypass = space;
				if(!proxyhost || !*proxyhost || !proxyport || !*proxyport) {
					logger(DEBUG_ALWAYS, LOG_ERR, "Host and port argument expected for proxy!");
					return false;
				}
				proxyhost = xstrdup(proxyhost);
				proxyport = xstrdup(proxyport);
				if(proxyuser && *proxyuser)
					proxyuser = xstrdup(proxyuser);
				if(proxypass && *proxypass)
					proxypass = xstrdup(proxypass);
				break;
		}

		free(proxy);
	}

	if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice) && choice)
		myself->options |= OPTION_INDIRECT;

	if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice) && choice)
		myself->options |= OPTION_TCPONLY;

	if(myself->options & OPTION_TCPONLY)
		myself->options |= OPTION_INDIRECT;

	get_config_bool(lookup_config(config_tree, "DirectOnly"), &directonly);
	get_config_bool(lookup_config(config_tree, "LocalDiscovery"), &localdiscovery);

	if(get_config_string(lookup_config(config_tree, "Mode"), &rmode)) {
		if(!strcasecmp(rmode, "router"))
			routing_mode = RMODE_ROUTER;
		else if(!strcasecmp(rmode, "switch"))
			routing_mode = RMODE_SWITCH;
		else if(!strcasecmp(rmode, "hub"))
			routing_mode = RMODE_HUB;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid routing mode!");
			return false;
		}
		free(rmode);
	}

	if(get_config_string(lookup_config(config_tree, "Forwarding"), &fmode)) {
		if(!strcasecmp(fmode, "off"))
			forwarding_mode = FMODE_OFF;
		else if(!strcasecmp(fmode, "internal"))
			forwarding_mode = FMODE_INTERNAL;
		else if(!strcasecmp(fmode, "kernel"))
			forwarding_mode = FMODE_KERNEL;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid forwarding mode!");
			return false;
		}
		free(fmode);
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
	get_config_bool(lookup_config(config_tree, "DecrementTTL"), &decrement_ttl);
	if(get_config_string(lookup_config(config_tree, "Broadcast"), &bmode)) {
		if(!strcasecmp(bmode, "no"))
			broadcast_mode = BMODE_NONE;
		else if(!strcasecmp(bmode, "yes") || !strcasecmp(bmode, "mst"))
			broadcast_mode = BMODE_MST;
		else if(!strcasecmp(bmode, "direct"))
			broadcast_mode = BMODE_DIRECT;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid broadcast mode!");
			return false;
		}
		free(bmode);
	}

	const char* const DEFAULT_BROADCAST_SUBNETS[] = { "ff:ff:ff:ff:ff:ff", "255.255.255.255", "224.0.0.0/4", "ff00::/8" };
	for (size_t i = 0; i < sizeof(DEFAULT_BROADCAST_SUBNETS) / sizeof(*DEFAULT_BROADCAST_SUBNETS); i++) {
		subnet_t *s = new_subnet();
		if (!str2net(s, DEFAULT_BROADCAST_SUBNETS[i]))
			abort();
		subnet_add(NULL, s);
	}
	for (config_t* cfg = lookup_config(config_tree, "BroadcastSubnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		subnet_t *s;
		if (!get_config_subnet(cfg, &s))
			continue;
		subnet_add(NULL, s);
	}

#if !defined(SOL_IP) || !defined(IP_TOS)
	if(priorityinheritance)
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "PriorityInheritance");
#endif

	if(!get_config_int(lookup_config(config_tree, "MACExpire"), &macexpire))
		macexpire = 600;

	if(get_config_int(lookup_config(config_tree, "MaxTimeout"), &maxtimeout)) {
		if(maxtimeout <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus maximum timeout!");
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
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid address family!");
			return false;
		}
		free(afname);
	}

	get_config_bool(lookup_config(config_tree, "Hostnames"), &hostnames);

	if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime))
		keylifetime = 3600;

	config_t *cfg = lookup_config(config_tree, "AutoConnect");
	if(cfg) {
		if(!get_config_bool(cfg, &autoconnect)) {
			// Some backwards compatibility with when this option was an int
			int val = 0;
			get_config_int(cfg, &val);
			autoconnect = val;
		}
	}

	get_config_bool(lookup_config(config_tree, "DisableBuggyPeers"), &disablebuggypeers);

	read_invitation_key();

	return true;
}

/*
  Add listening sockets.
*/
static bool add_listen_address(char *address, bool bindto) {
	char *port = myport;

	if(address) {
		char *space = strchr(address, ' ');
		if(space) {
			*space++ = 0;
			port = space;
		}

		if(!strcmp(address, "*"))
			*address = 0;
	}

	struct addrinfo *ai, hint = {0};
	hint.ai_family = addressfamily;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_flags = AI_PASSIVE;

	int err = getaddrinfo(address && *address ? address : NULL, port, &hint, &ai);
	free(address);

	if(err || !ai) {
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "getaddrinfo", err == EAI_SYSTEM ? strerror(err) : gai_strerror(err));
		return false;
	}

	for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
		// Ignore duplicate addresses
		bool found = false;

		for(int i = 0; i < listen_sockets; i++)
			if(!memcmp(&listen_socket[i].sa, aip->ai_addr, aip->ai_addrlen)) {
				found = true;
				break;
			}

		if(found)
			continue;

		if(listen_sockets >= MAXSOCKETS) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
			return false;
		}

		int tcp_fd = setup_listen_socket((sockaddr_t *) aip->ai_addr);

		if(tcp_fd < 0)
			continue;

		int udp_fd = setup_vpn_in_socket((sockaddr_t *) aip->ai_addr);

		if(tcp_fd < 0) {
			close(tcp_fd);
			continue;
		}

		io_add(&listen_socket[listen_sockets].tcp, handle_new_meta_connection, &listen_socket[listen_sockets], tcp_fd, IO_READ);
		io_add(&listen_socket[listen_sockets].udp, handle_incoming_vpn_data, &listen_socket[listen_sockets], udp_fd, IO_READ);

		if(debug_level >= DEBUG_CONNECTIONS) {
			char *hostname = sockaddr2hostname((sockaddr_t *) aip->ai_addr);
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s", hostname);
			free(hostname);
		}

		listen_socket[listen_sockets].bindto = bindto;
		memcpy(&listen_socket[listen_sockets].sa, aip->ai_addr, aip->ai_addrlen);
		listen_sockets++;
	}

	freeaddrinfo(ai);
	return true;
}

void device_enable(void) {
	if (devops.enable)
		devops.enable();

	/* Run tinc-up script to further initialize the tap interface */

	char *envp[5] = {NULL};
	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myname);

	execute_script("tinc-up", envp);

	for(int i = 0; i < 4; i++)
		free(envp[i]);
}

void device_disable(void) {
	char *envp[5] = {NULL};
	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myname);

	execute_script("tinc-down", envp);

	for(int i = 0; i < 4; i++)
		free(envp[i]);

	if (devops.disable)
		devops.disable();
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
static bool setup_myself(void) {
	char *name, *hostname, *cipher, *digest, *type;
	char *address = NULL;
	bool port_specified = false;

	if(!(name = get_name())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Name for tinc daemon required!");
		return false;
	}

	myname = xstrdup(name);
	myself = new_node();
	myself->connection = new_connection();
	myself->name = name;
	myself->connection->name = xstrdup(name);
	read_host_config(config_tree, name);

	if(!get_config_string(lookup_config(config_tree, "Port"), &myport))
		myport = xstrdup("655");
	else
		port_specified = true;

	myself->connection->options = 0;
	myself->connection->protocol_major = PROT_MAJOR;
	myself->connection->protocol_minor = PROT_MINOR;

	myself->options |= PROT_MINOR << 24;

	if(!get_config_bool(lookup_config(config_tree, "ExperimentalProtocol"), &experimental)) {
		experimental = read_ecdsa_private_key();
		if(!experimental)
			logger(DEBUG_ALWAYS, LOG_WARNING, "Support for SPTPS disabled.");
	} else {
		if(experimental && !read_ecdsa_private_key())
			return false;
	}

	if(!read_rsa_private_key()) {
		if(experimental) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Support for legacy protocol disabled.");
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "No private keys available, cannot start tinc!");
			return false;
		}
	}

	/* Ensure myport is numeric */

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

	for(config_t *cfg = lookup_config(config_tree, "Subnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		subnet_t *subnet;

		if(!get_config_subnet(cfg, &subnet))
			return false;

		subnet_add(myself, subnet);
	}

	/* Check some options */

	if(!setup_myself_reloadable())
		return false;

	get_config_bool(lookup_config(config_tree, "StrictSubnets"), &strictsubnets);
	get_config_bool(lookup_config(config_tree, "TunnelServer"), &tunnelserver);
	strictsubnets |= tunnelserver;

	if(get_config_int(lookup_config(config_tree, "MaxConnectionBurst"), &max_connection_burst)) {
		if(max_connection_burst <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "MaxConnectionBurst cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(config_tree, "UDPRcvBuf"), &udp_rcvbuf)) {
		if(udp_rcvbuf <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPRcvBuf cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(config_tree, "UDPSndBuf"), &udp_sndbuf)) {
		if(udp_sndbuf <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPSndBuf cannot be negative!");
			return false;
		}
	}

	int replaywin_int;
	if(get_config_int(lookup_config(config_tree, "ReplayWindow"), &replaywin_int)) {
		if(replaywin_int < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "ReplayWindow cannot be negative!");
			return false;
		}
		replaywin = (unsigned)replaywin_int;
		sptps_replaywin = replaywin;
	}

	/* Generate packet encryption key */

	if(!get_config_string(lookup_config(config_tree, "Cipher"), &cipher))
		cipher = xstrdup("blowfish");

	if(!strcasecmp(cipher, "none")) {
		myself->incipher = NULL;
	} else if(!(myself->incipher = cipher_open_by_name(cipher))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unrecognized cipher type!");
		return false;
	}

	free(cipher);

	timeout_add(&keyexpire_timeout, keyexpire_handler, &keyexpire_timeout, &(struct timeval){keylifetime, rand() % 100000});

	/* Check if we want to use message authentication codes... */

	int maclength = 4;
	get_config_int(lookup_config(config_tree, "MACLength"), &maclength);

	if(maclength < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Bogus MAC length!");
		return false;
	}

	if(!get_config_string(lookup_config(config_tree, "Digest"), &digest))
		digest = xstrdup("sha1");

	if(!strcasecmp(digest, "none")) {
		myself->indigest = NULL;
	} else if(!(myself->indigest = digest_open_by_name(digest, maclength))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unrecognized digest type!");
		return false;
	}

	free(digest);

	/* Compression */

	if(get_config_int(lookup_config(config_tree, "Compression"), &myself->incompression)) {
		if(myself->incompression < 0 || myself->incompression > 11) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus compression level!");
			return false;
		}
	} else
		myself->incompression = 0;

	myself->connection->outcompression = 0;

	/* Done */

	myself->nexthop = myself;
	myself->via = myself;
	myself->status.reachable = true;
	myself->last_state_change = now.tv_sec;
	myself->status.sptps = experimental;
	node_add(myself);

	graph();

	if(strictsubnets)
		load_all_subnets();
	else if(autoconnect)
		load_all_nodes();

	/* Open device */

	devops = os_devops;

	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "dummy"))
			devops = dummy_devops;
		else if(!strcasecmp(type, "raw_socket"))
			devops = raw_socket_devops;
		else if(!strcasecmp(type, "multicast"))
			devops = multicast_devops;
#ifdef ENABLE_UML
		else if(!strcasecmp(type, "uml"))
			devops = uml_devops;
#endif
#ifdef ENABLE_VDE
		else if(!strcasecmp(type, "vde"))
			devops = vde_devops;
#endif
	}

	get_config_bool(lookup_config(config_tree, "DeviceStandby"), &device_standby);

	if(!devops.setup())
		return false;

	if(device_fd >= 0)
		io_add(&device_io, handle_device_data, NULL, device_fd, IO_READ);

	/* Open sockets */

	if(!do_detach && getenv("LISTEN_FDS")) {
		sockaddr_t sa;
		socklen_t salen;

		listen_sockets = atoi(getenv("LISTEN_FDS"));
#ifdef HAVE_UNSETENV
		unsetenv("LISTEN_FDS");
#endif

		if(listen_sockets > MAXSOCKETS) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
			return false;
		}

		for(int i = 0; i < listen_sockets; i++) {
			salen = sizeof sa;
			if(getsockname(i + 3, &sa.sa, &salen) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Could not get address of listen fd %d: %s", i + 3, sockstrerror(sockerrno));
				return false;
			}

#ifdef FD_CLOEXEC
			fcntl(i + 3, F_SETFD, FD_CLOEXEC);
#endif

			int udp_fd = setup_vpn_in_socket(&sa);
			if(udp_fd < 0)
				return false;

			io_add(&listen_socket[i].tcp, (io_cb_t)handle_new_meta_connection, &listen_socket[i], i + 3, IO_READ);
			io_add(&listen_socket[i].udp, (io_cb_t)handle_incoming_vpn_data, &listen_socket[i], udp_fd, IO_READ);

			if(debug_level >= DEBUG_CONNECTIONS) {
				hostname = sockaddr2hostname(&sa);
				logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s", hostname);
				free(hostname);
			}

			memcpy(&listen_socket[i].sa, &sa, salen);
		}
	} else {
		listen_sockets = 0;
		int cfgs = 0;

		for(config_t *cfg = lookup_config(config_tree, "BindToAddress"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			cfgs++;
			get_config_string(cfg, &address);
			if(!add_listen_address(address, true))
				return false;
		}

		for(config_t *cfg = lookup_config(config_tree, "ListenAddress"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			cfgs++;
			get_config_string(cfg, &address);
			if(!add_listen_address(address, false))
				return false;
		}

		if(!cfgs)
			if(!add_listen_address(address, NULL))
				return false;
	}

	if(!listen_sockets) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to create any listening socket!");
		return false;
	}

	/* If no Port option was specified, set myport to the port used by the first listening socket. */

	if(!port_specified || atoi(myport) == 0) {
		sockaddr_t sa;
		socklen_t salen = sizeof sa;
		if(!getsockname(listen_socket[0].udp.fd, &sa.sa, &salen)) {
			free(myport);
			sockaddr2str(&sa, NULL, &myport);
			if(!myport)
				myport = xstrdup("655");
		}
	}

	xasprintf(&myself->hostname, "MYSELF port %s", myport);
	myself->connection->hostname = xstrdup(myself->hostname);

	/* Done. */

	last_config_check = now.tv_sec;

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

	if(!init_control())
		return false;

	if (!device_standby)
		device_enable();

	/* Run subnet-up scripts for our own subnets */

	subnet_update(myself, NULL, true);

	return true;
}

/*
  close all open network connections
*/
void close_network_connections(void) {
	for(list_node_t *node = connection_list->head, *next; node; node = next) {
		next = node->next;
		connection_t *c = node->data;
		/* Keep control connections open until the end, so they know when we really terminated */
		if(c->status.control)
			c->socket = -1;
		c->outgoing = NULL;
		terminate_connection(c, false);
	}

	if(outgoing_list)
		list_delete_list(outgoing_list);

	if(myself && myself->connection) {
		subnet_update(myself, NULL, false);
		terminate_connection(myself->connection, false);
		free_connection(myself->connection);
	}

	for(int i = 0; i < listen_sockets; i++) {
		io_del(&listen_socket[i].tcp);
		io_del(&listen_socket[i].udp);
		close(listen_socket[i].tcp.fd);
		close(listen_socket[i].udp.fd);
	}

	exit_requests();
	exit_edges();
	exit_subnets();
	exit_nodes();
	exit_connections();

	if (!device_standby)
		device_disable();

	free(myport);

	if (device_fd >= 0)
		io_del(&device_io);
	if (devops.close)
		devops.close();

	exit_control();

	free(myname);
	free(scriptextension);
	free(scriptinterpreter);

	return;
}
