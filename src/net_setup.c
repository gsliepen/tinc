/*
    net_setup.c -- Setup.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2021 Guus Sliepen <guus@tinc-vpn.org>
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
#include "conf_net.h"
#include "conf.h"
#include "connection.h"
#include "compression.h"
#include "control.h"
#include "crypto.h"
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
#include "script.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"
#include "keys.h"
#include "sandbox.h"

#ifdef HAVE_MINIUPNPC
#include "upnp.h"
#endif

ports_t myport;
static io_t device_io;
devops_t devops;
bool device_standby = false;

char *proxyhost = NULL;
char *proxyport = NULL;
char *proxyuser = NULL;
char *proxypass = NULL;

proxytype_t proxytype;
bool autoconnect;
bool disablebuggypeers;

char *scriptinterpreter;
char *scriptextension;

bool node_read_ecdsa_public_key(node_t *n) {
	if(ecdsa_active(n->ecdsa)) {
		return true;
	}

	FILE *fp;
	char *pubname = NULL;
	char *p;

	splay_tree_t config;
	init_configuration(&config);

	if(!read_host_config(&config, n->name, true)) {
		goto exit;
	}

	/* First, check for simple Ed25519PublicKey statement */

	if(get_config_string(lookup_config(&config, "Ed25519PublicKey"), &p)) {
		n->ecdsa = ecdsa_set_base64_public_key(p);
		free(p);
		goto exit;
	}

	/* Else, check for Ed25519PublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(&config, "Ed25519PublicKeyFile"), &pubname)) {
		xasprintf(&pubname, "%s" SLASH "hosts" SLASH "%s", confbase, n->name);
	}

	fp = fopen(pubname, "r");

	if(!fp) {
		goto exit;
	}

	n->ecdsa = ecdsa_read_pem_public_key(fp);
	fclose(fp);

exit:
	splay_empty_tree(&config);
	free(pubname);
	return n->ecdsa;
}

static bool read_invitation_key(void) {
	FILE *fp;
	char fname[PATH_MAX];

	if(invitation_key) {
		ecdsa_free(invitation_key);
		invitation_key = NULL;
	}

	snprintf(fname, sizeof(fname), "%s" SLASH "invitations" SLASH "ed25519_key.priv", confbase);

	fp = fopen(fname, "r");

	if(fp) {
		invitation_key = ecdsa_read_pem_private_key(fp);
		fclose(fp);

		if(!invitation_key) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Reading Ed25519 private key file `%s' failed", fname);
		}
	}

	return invitation_key;
}

#ifndef DISABLE_LEGACY
static timeout_t keyexpire_timeout;

static void keyexpire_handler(void *data) {
	regenerate_key();
	timeout_set(data, &(struct timeval) {
		keylifetime, jitter()
	});
}
#endif

void regenerate_key(void) {
	logger(DEBUG_STATUS, LOG_INFO, "Expiring symmetric keys");
	send_key_changed();

	for splay_each(node_t, n, &node_tree) {
		n->status.validkey_in = false;
	}
}

void load_all_nodes(void) {
	DIR *dir;
	struct dirent *ent;
	char dname[PATH_MAX];

	snprintf(dname, sizeof(dname), "%s" SLASH "hosts", confbase);
	dir = opendir(dname);

	if(!dir) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", dname, strerror(errno));
		return;
	}

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name)) {
			continue;
		}

		node_t *n = lookup_node(ent->d_name);

		splay_tree_t config;
		init_configuration(&config);
		read_config_options(&config, ent->d_name);
		read_host_config(&config, ent->d_name, true);

		if(!n) {
			n = new_node(ent->d_name);
			node_add(n);
		}

		if(strictsubnets) {
			for(config_t *cfg = lookup_config(&config, "Subnet"); cfg; cfg = lookup_config_next(&config, cfg)) {
				subnet_t *s, *s2;

				if(!get_config_subnet(cfg, &s)) {
					continue;
				}

				if((s2 = lookup_subnet(n, s))) {
					s2->expires = -1;
					free(s);
				} else {
					subnet_add(n, s);
				}
			}
		}

		if(lookup_config(&config, "Address")) {
			n->status.has_address = true;
		}

		splay_empty_tree(&config);
	}

	closedir(dir);
}

char *get_name(void) {
	char *name = NULL;
	char *returned_name;

	get_config_string(lookup_config(&config_tree, "Name"), &name);

	if(!name) {
		return NULL;
	}

	returned_name = replace_name(name);
	free(name);
	return returned_name;
}

static void read_interpreter(void) {
	char *interpreter = NULL;
	get_config_string(lookup_config(&config_tree, "ScriptsInterpreter"), &interpreter);

	if(!interpreter || (sandbox_can(START_PROCESSES, AFTER_SANDBOX) && sandbox_can(USE_NEW_PATHS, AFTER_SANDBOX))) {
		free(scriptinterpreter);
		scriptinterpreter = interpreter;
		return;
	}

	if(!string_eq(interpreter, scriptinterpreter)) {
		logger(DEBUG_ALWAYS, LOG_NOTICE, "Not changing ScriptsInterpreter because of sandbox.");
	}

	free(interpreter);
}

bool setup_myself_reloadable(void) {
	read_interpreter();

	free(scriptextension);

	if(!get_config_string(lookup_config(&config_tree, "ScriptsExtension"), &scriptextension)) {
		scriptextension = xstrdup("");
	}

	char *proxy = NULL;

	get_config_string(lookup_config(&config_tree, "Proxy"), &proxy);

	if(proxy) {
		char *space;

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
			if(sandbox_can(START_PROCESSES, AFTER_SANDBOX)) {
				proxytype = PROXY_EXEC;
			} else {
				logger(DEBUG_ALWAYS, LOG_ERR, "Cannot use exec proxies with current sandbox level.");
				return false;
			}
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type %s!", proxy);
			free_string(proxy);
			return false;
		}

		free(proxyhost);
		proxyhost = NULL;

		free(proxyport);
		proxyport = NULL;

		free_string(proxyuser);
		proxyuser = NULL;

		free_string(proxypass);
		proxypass = NULL;

		switch(proxytype) {
		case PROXY_NONE:
		default:
			break;

		case PROXY_EXEC:
			if(!space || !*space) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Argument expected for proxy type exec!");
				free_string(proxy);
				return false;
			}

			if(!sandbox_can(USE_NEW_PATHS, AFTER_SANDBOX)) {
				logger(DEBUG_ALWAYS, LOG_NOTICE, "Changed exec proxy may fail to work because of sandbox.");
			}

			proxyhost = xstrdup(space);
			break;

		case PROXY_SOCKS4:
		case PROXY_SOCKS4A:
		case PROXY_SOCKS5:
		case PROXY_HTTP:
			proxyhost = space;

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxyport = space;
			}

			if(!proxyhost || !*proxyhost || !proxyport || !*proxyport) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Host and port argument expected for proxy!");
				proxyport = NULL;
				proxyhost = NULL;
				free_string(proxy);
				return false;
			}

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxyuser = space;
			}

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxypass = space;
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

		free_string(proxy);
	}

	bool choice;

	if(get_config_bool(lookup_config(&config_tree, "IndirectData"), &choice) && choice) {
		myself->options |= OPTION_INDIRECT;
	}

	if(get_config_bool(lookup_config(&config_tree, "TCPOnly"), &choice) && choice) {
		myself->options |= OPTION_TCPONLY;
	}

	if(myself->options & OPTION_TCPONLY) {
		myself->options |= OPTION_INDIRECT;
	}

	get_config_bool(lookup_config(&config_tree, "UDPDiscovery"), &udp_discovery);
	get_config_int(lookup_config(&config_tree, "UDPDiscoveryKeepaliveInterval"), &udp_discovery_keepalive_interval);
	get_config_int(lookup_config(&config_tree, "UDPDiscoveryInterval"), &udp_discovery_interval);
	get_config_int(lookup_config(&config_tree, "UDPDiscoveryTimeout"), &udp_discovery_timeout);

	get_config_int(lookup_config(&config_tree, "MTUInfoInterval"), &mtu_info_interval);
	get_config_int(lookup_config(&config_tree, "UDPInfoInterval"), &udp_info_interval);

	get_config_bool(lookup_config(&config_tree, "DirectOnly"), &directonly);
	get_config_bool(lookup_config(&config_tree, "LocalDiscovery"), &localdiscovery);

	char *rmode = NULL;

	if(get_config_string(lookup_config(&config_tree, "Mode"), &rmode)) {
		if(!strcasecmp(rmode, "router")) {
			routing_mode = RMODE_ROUTER;
		} else if(!strcasecmp(rmode, "switch")) {
			routing_mode = RMODE_SWITCH;
		} else if(!strcasecmp(rmode, "hub")) {
			routing_mode = RMODE_HUB;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid routing mode!");
			free(rmode);
			return false;
		}

		free(rmode);
	}

	char *fmode = NULL;

	if(get_config_string(lookup_config(&config_tree, "Forwarding"), &fmode)) {
		if(!strcasecmp(fmode, "off")) {
			forwarding_mode = FMODE_OFF;
		} else if(!strcasecmp(fmode, "internal")) {
			forwarding_mode = FMODE_INTERNAL;
		} else if(!strcasecmp(fmode, "kernel")) {
			forwarding_mode = FMODE_KERNEL;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid forwarding mode!");
			free(fmode);
			return false;
		}

		free(fmode);
	}

	choice = !(myself->options & OPTION_TCPONLY);
	get_config_bool(lookup_config(&config_tree, "PMTUDiscovery"), &choice);

	if(choice) {
		myself->options |= OPTION_PMTU_DISCOVERY;
	}

	choice = true;
	get_config_bool(lookup_config(&config_tree, "ClampMSS"), &choice);

	if(choice) {
		myself->options |= OPTION_CLAMP_MSS;
	}

	get_config_bool(lookup_config(&config_tree, "PriorityInheritance"), &priorityinheritance);
	get_config_bool(lookup_config(&config_tree, "DecrementTTL"), &decrement_ttl);

	char *bmode = NULL;

	if(get_config_string(lookup_config(&config_tree, "Broadcast"), &bmode)) {
		if(!strcasecmp(bmode, "no")) {
			broadcast_mode = BMODE_NONE;
		} else if(!strcasecmp(bmode, "yes") || !strcasecmp(bmode, "mst")) {
			broadcast_mode = BMODE_MST;
		} else if(!strcasecmp(bmode, "direct")) {
			broadcast_mode = BMODE_DIRECT;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid broadcast mode!");
			free(bmode);
			return false;
		}

		free(bmode);
	}

	/* Delete all broadcast subnets before re-adding them */

	for splay_each(subnet_t, s, &subnet_tree) {
		if(!s->owner) {
			splay_delete_node(&subnet_tree, node);
		}
	}

	const char *const DEFAULT_BROADCAST_SUBNETS[] = { "ff:ff:ff:ff:ff:ff", "255.255.255.255", "224.0.0.0/4", "ff00::/8" };

	for(size_t i = 0; i < sizeof(DEFAULT_BROADCAST_SUBNETS) / sizeof(*DEFAULT_BROADCAST_SUBNETS); i++) {
		subnet_t *s = new_subnet();

		if(!str2net(s, DEFAULT_BROADCAST_SUBNETS[i])) {
			abort();
		}

		subnet_add(NULL, s);
	}

	for(config_t *cfg = lookup_config(&config_tree, "BroadcastSubnet"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		subnet_t *s;

		if(!get_config_subnet(cfg, &s)) {
			continue;
		}

		subnet_add(NULL, s);
	}

#if !defined(IP_TOS)

	if(priorityinheritance) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform for IPv4 connections", "PriorityInheritance");
	}

#endif

#if !defined(IPV6_TCLASS)

	if(priorityinheritance) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform for IPv6 connections", "PriorityInheritance");
	}

#endif

	if(!get_config_int(lookup_config(&config_tree, "MACExpire"), &macexpire)) {
		macexpire = 600;
	}

	if(get_config_int(lookup_config(&config_tree, "MaxTimeout"), &maxtimeout)) {
		if(maxtimeout <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus maximum timeout!");
			return false;
		}
	} else {
		maxtimeout = 900;
	}

	char *afname = NULL;

	if(get_config_string(lookup_config(&config_tree, "AddressFamily"), &afname)) {
		if(!strcasecmp(afname, "IPv4")) {
			addressfamily = AF_INET;
		} else if(!strcasecmp(afname, "IPv6")) {
			addressfamily = AF_INET6;
		} else if(!strcasecmp(afname, "any")) {
			addressfamily = AF_UNSPEC;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid address family!");
			free(afname);
			return false;
		}

		free(afname);
	}

	get_config_bool(lookup_config(&config_tree, "Hostnames"), &hostnames);

	if(!get_config_int(lookup_config(&config_tree, "KeyExpire"), &keylifetime)) {
		keylifetime = 3600;
	}

	if(!get_config_bool(lookup_config(&config_tree, "AutoConnect"), &autoconnect)) {
		autoconnect = true;
	}

	get_config_bool(lookup_config(&config_tree, "DisableBuggyPeers"), &disablebuggypeers);

	if(!get_config_int(lookup_config(&config_tree, "InvitationExpire"), &invitation_lifetime)) {
		invitation_lifetime = 604800;        // 1 week
	}

	read_invitation_key();

	return true;
}

// Get the port that `from_fd` is listening on, and assign it to
// `sa` if `sa` has a dynamically allocated (zero) port.
static bool assign_static_port(sockaddr_t *sa, int from_fd) {
	// We cannot get a port from a bad FD. Bail out.
	if(from_fd <= 0) {
		return false;
	}

	int port = get_bound_port(from_fd);

	if(!port) {
		return false;
	}

	// If the port is non-zero, don't reassign it as it's already static.
	switch(sa->sa.sa_family) {
	case AF_INET:
		if(!sa->in.sin_port) {
			sa->in.sin_port = htons(port);
		}

		return true;

	case AF_INET6:
		if(!sa->in6.sin6_port) {
			sa->in6.sin6_port = htons(port);
		}

		return true;

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown address family 0x%x", sa->sa.sa_family);
		return false;
	}
}

typedef int (*bind_fn_t)(const sockaddr_t *);

static int bind_reusing_port(const sockaddr_t *sa, int from_fd, bind_fn_t setup) {
	sockaddr_t reuse_sa;
	memcpy(&reuse_sa, sa, SALEN(sa->sa));

	int fd = -1;

	// Check if the address we've been passed here is using port 0.
	// If it is, try to get an actual port from an already bound socket, and reuse it here.
	if(assign_static_port(&reuse_sa, from_fd)) {
		fd = setup(&reuse_sa);
	}

	// If we're binding to a hardcoded non-zero port, or no socket is listening yet,
	// or binding failed, try the original address.
	if(fd < 0) {
		fd = setup(sa);
	}

	return fd;
}

/*
  Add listening sockets.
*/
static bool add_listen_address(char *address, bool bindto) {
	char *port = myport.tcp;

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

	struct addrinfo *ai, hint = {0};

	hint.ai_family = addressfamily;

	hint.ai_socktype = SOCK_STREAM;

	hint.ai_protocol = IPPROTO_TCP;

	hint.ai_flags = AI_PASSIVE;

#if HAVE_DECL_RES_INIT
	res_init();

#endif
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

		if(found) {
			continue;
		}

		if(listen_sockets >= MAXSOCKETS) {
			listen_sockets = MAXSOCKETS;
			logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
			freeaddrinfo(ai);
			return false;
		}

		const sockaddr_t *sa = (sockaddr_t *) aip->ai_addr;
		int from_fd = listen_socket[0].tcp.fd;

		// If we're binding to a dynamically allocated (zero) port, try to get the actual
		// port of the first TCP socket, and use it for this one. If that succeeds, our
		// tincd instance will use the same port for all addresses it listens on.
		int tcp_fd = bind_reusing_port(sa, from_fd, setup_listen_socket);

		if(tcp_fd < 0) {
			continue;
		}

		// If we just successfully bound the first socket, use it for the UDP procedure below.
		// Otherwise, keep using the socket we've obtained from listen_socket[0].
		if(!from_fd) {
			from_fd = tcp_fd;
		}

		int udp_fd = bind_reusing_port(sa, from_fd, setup_vpn_in_socket);

		if(udp_fd < 0) {
			closesocket(tcp_fd);
			continue;
		}

		listen_socket_t *sock = &listen_socket[listen_sockets];
		io_add(&sock->tcp, handle_new_meta_connection, sock, tcp_fd, IO_READ);
		io_add(&sock->udp, handle_incoming_vpn_data, sock, udp_fd, IO_READ);

		if(debug_level >= DEBUG_CONNECTIONS) {
			int tcp_port = get_bound_port(tcp_fd);
			char *hostname = NULL;
			sockaddr2str(sa, &hostname, NULL);
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s port %d", hostname, tcp_port);
			free(hostname);
		}

		sock->bindto = bindto;
		memcpy(&sock->sa, aip->ai_addr, aip->ai_addrlen);
		listen_sockets++;
	}

	freeaddrinfo(ai);
	return true;
}

void device_enable(void) {
	if(devops.enable) {
		devops.enable();
	}

	/* Run tinc-up script to further initialize the tap interface */

	environment_t env;
	environment_init(&env);
	execute_script("tinc-up", &env);
	environment_exit(&env);
}

void device_disable(void) {
	environment_t env;
	environment_init(&env);
	execute_script("tinc-down", &env);
	environment_exit(&env);

	if(devops.disable) {
		devops.disable();
	}
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
static bool setup_myself(void) {
	char *name, *type;
	char *address = NULL;
	bool port_specified = false;

	if(!(name = get_name())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Name for tinc daemon required!");
		return false;
	}

	myname = xstrdup(name);
	myself = new_node(name);
	myself->connection = new_connection();
	myself->connection->name = name;
	read_host_config(&config_tree, name, true);

	if(!get_config_string(lookup_config(&config_tree, "Port"), &myport.tcp)) {
		myport.tcp = xstrdup("655");
	} else {
		port_specified = true;
	}

	myport.udp = xstrdup(myport.tcp);

	myself->connection->options = 0;
	myself->connection->protocol_major = PROT_MAJOR;
	myself->connection->protocol_minor = PROT_MINOR;

	myself->options |= PROT_MINOR << 24;

#ifdef DISABLE_LEGACY
	myself->connection->ecdsa = read_ecdsa_private_key(&config_tree, NULL);
	experimental = myself->connection->ecdsa != NULL;

	if(!experimental) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No private key available, cannot start tinc!");
		return false;
	}

#else

	if(!get_config_bool(lookup_config(&config_tree, "ExperimentalProtocol"), &experimental)) {
		myself->connection->ecdsa = read_ecdsa_private_key(&config_tree, NULL);
		experimental = myself->connection->ecdsa != NULL;

		if(!experimental) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Support for SPTPS disabled.");
		}
	} else {
		if(experimental) {
			myself->connection->ecdsa = read_ecdsa_private_key(&config_tree, NULL);

			if(!myself->connection->ecdsa) {
				return false;
			}
		}
	}

	rsa_t *rsa = read_rsa_private_key(&config_tree, NULL);

	if(rsa) {
		myself->connection->legacy = new_legacy_ctx(rsa);
	} else {
		if(experimental) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Support for legacy protocol disabled.");
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "No private keys available, cannot start tinc!");
			return false;
		}
	}

#endif

	/* Ensure myport is numeric */
	if(!is_decimal(myport.tcp)) {
		uint16_t port = service_to_port(myport.tcp);

		if(!port) {
			return false;
		}

		free(myport.tcp);
		myport.tcp = int_to_str(port);

		free(myport.udp);
		myport.udp = xstrdup(myport.tcp);
	}

	/* Read in all the subnets specified in the host configuration file */

	for(config_t *cfg = lookup_config(&config_tree, "Subnet"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		subnet_t *subnet;

		if(!get_config_subnet(cfg, &subnet)) {
			return false;
		}

		subnet_add(myself, subnet);
	}

	/* Check some options */

	if(!setup_myself_reloadable()) {
		return false;
	}

	get_config_bool(lookup_config(&config_tree, "StrictSubnets"), &strictsubnets);
	get_config_bool(lookup_config(&config_tree, "TunnelServer"), &tunnelserver);
	strictsubnets |= tunnelserver;

	if(get_config_int(lookup_config(&config_tree, "MaxConnectionBurst"), &max_connection_burst)) {
		if(max_connection_burst <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "MaxConnectionBurst cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(&config_tree, "UDPRcvBuf"), &udp_rcvbuf)) {
		if(udp_rcvbuf < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPRcvBuf cannot be negative!");
			return false;
		}

		udp_rcvbuf_warnings = true;
	}

	if(get_config_int(lookup_config(&config_tree, "UDPSndBuf"), &udp_sndbuf)) {
		if(udp_sndbuf < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPSndBuf cannot be negative!");
			return false;
		}

		udp_sndbuf_warnings = true;
	}

	get_config_int(lookup_config(&config_tree, "FWMark"), &fwmark);
#ifndef SO_MARK

	if(fwmark) {
		logger(DEBUG_ALWAYS, LOG_ERR, "FWMark not supported on this platform!");
		return false;
	}

#endif

	int replaywin_int;

	if(get_config_int(lookup_config(&config_tree, "ReplayWindow"), &replaywin_int)) {
		if(replaywin_int < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "ReplayWindow cannot be negative!");
			return false;
		}

		replaywin = (unsigned)replaywin_int;
		sptps_replaywin = replaywin;
	}

#ifndef DISABLE_LEGACY
	/* Generate packet encryption key */

	char *cipher;

	if(!get_config_string(lookup_config(&config_tree, "Cipher"), &cipher)) {
		cipher = xstrdup("aes-256-cbc");
	}

	if(!strcasecmp(cipher, "none")) {
		myself->incipher = NULL;
	} else {
		myself->incipher = cipher_alloc();

		if(!cipher_open_by_name(myself->incipher, cipher)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unrecognized cipher type!");
			cipher_free(myself->incipher);
			myself->incipher = NULL;
			free(cipher);
			return false;
		}
	}

	free(cipher);

	timeout_add(&keyexpire_timeout, keyexpire_handler, &keyexpire_timeout, &(struct timeval) {
		keylifetime, jitter()
	});

	/* Check if we want to use message authentication codes... */

	int maclength = 4;
	get_config_int(lookup_config(&config_tree, "MACLength"), &maclength);

	if(maclength < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Bogus MAC length!");
		return false;
	}

	char *digest;

	if(!get_config_string(lookup_config(&config_tree, "Digest"), &digest)) {
		digest = xstrdup("sha256");
	}

	if(!strcasecmp(digest, "none")) {
		myself->indigest = NULL;
	} else {
		myself->indigest = digest_alloc();

		if(!digest_open_by_name(myself->indigest, digest, maclength)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unrecognized digest type!");
			digest_free(myself->indigest);
			myself->indigest = NULL;
			free(digest);
			return false;
		}
	}

	free(digest);
#endif

	/* Compression */
	int incompression = 0;

	if(get_config_int(lookup_config(&config_tree, "Compression"), &incompression)) {
		myself->incompression = incompression;

		switch(myself->incompression) {
		case COMPRESS_LZ4:
#ifdef HAVE_LZ4
			break;
#else
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus compression level!");
			logger(DEBUG_ALWAYS, LOG_ERR, "LZ4 compression is unavailable on this node.");
			return false;
#endif

		case COMPRESS_LZO_HI:
		case COMPRESS_LZO_LO:
#ifdef HAVE_LZO
			break;
#else
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus compression level!");
			logger(DEBUG_ALWAYS, LOG_ERR, "LZO compression is unavailable on this node.");
			return false;
#endif

		case COMPRESS_ZLIB_9:
		case COMPRESS_ZLIB_8:
		case COMPRESS_ZLIB_7:
		case COMPRESS_ZLIB_6:
		case COMPRESS_ZLIB_5:
		case COMPRESS_ZLIB_4:
		case COMPRESS_ZLIB_3:
		case COMPRESS_ZLIB_2:
		case COMPRESS_ZLIB_1:
#ifdef HAVE_ZLIB
			break;
#else
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus compression level!");
			logger(DEBUG_ALWAYS, LOG_ERR, "ZLIB compression is unavailable on this node.");
			return false;
#endif

		case COMPRESS_NONE:
			break;

		default:
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus compression level!");
			logger(DEBUG_ALWAYS, LOG_ERR, "Compression level %i is unrecognized by this node.", myself->incompression);
			return false;
		}
	} else {
		myself->incompression = COMPRESS_NONE;
	}

	/* Done */

	myself->nexthop = myself;
	myself->via = myself;
	myself->status.reachable = true;
	myself->last_state_change = now.tv_sec;
	myself->status.sptps = experimental;
	node_add(myself);

	graph();

	load_all_nodes();

	/* Open device */

	devops = os_devops;

	if(get_config_string(lookup_config(&config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, DEVICE_DUMMY)) {
			devops = dummy_devops;
		} else if(!strcasecmp(type, "raw_socket")) {
			devops = raw_socket_devops;
		} else if(!strcasecmp(type, "multicast")) {
			devops = multicast_devops;
		}

#ifdef HAVE_SYS_UN_H
		else if(!strcasecmp(type, "fd")) {
			devops = fd_devops;
		}

#endif
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

	get_config_bool(lookup_config(&config_tree, "DeviceStandby"), &device_standby);

	if(!devops.setup()) {
		return false;
	}

	if(device_fd >= 0) {
		io_add(&device_io, handle_device_data, NULL, device_fd, IO_READ);
	}

	/* Open sockets */

	const char *listen_fds = getenv("LISTEN_FDS");

	if(!do_detach && listen_fds) {
		sockaddr_t sa;
		socklen_t salen;

		listen_sockets = atoi(listen_fds);
#ifdef HAVE_UNSETENV
		unsetenv("LISTEN_FDS");
#endif

		if(listen_sockets > MAXSOCKETS) {
			listen_sockets = MAXSOCKETS;
			logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
			return false;
		}

		for(int i = 0; i < listen_sockets; i++) {
			const int tcp_fd = i + 3;
			salen = sizeof(sa);

			if(getsockname(tcp_fd, &sa.sa, &salen) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Could not get address of listen fd %d: %s", tcp_fd, sockstrerror(sockerrno));
				return false;
			}

#ifdef FD_CLOEXEC
			fcntl(tcp_fd, F_SETFD, FD_CLOEXEC);
#endif

			int udp_fd = setup_vpn_in_socket(&sa);

			if(udp_fd < 0) {
				return false;
			}

			io_add(&listen_socket[i].tcp, (io_cb_t)handle_new_meta_connection, &listen_socket[i], tcp_fd, IO_READ);
			io_add(&listen_socket[i].udp, (io_cb_t)handle_incoming_vpn_data, &listen_socket[i], udp_fd, IO_READ);

			if(debug_level >= DEBUG_CONNECTIONS) {
				char *hostname = sockaddr2hostname(&sa);
				logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s", hostname);
				free(hostname);
			}

			memcpy(&listen_socket[i].sa, &sa, salen);
		}
	} else {
		listen_sockets = 0;
		int cfgs = 0;

		for(config_t *cfg = lookup_config(&config_tree, "BindToAddress"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
			cfgs++;
			get_config_string(cfg, &address);

			if(!add_listen_address(address, true)) {
				return false;
			}
		}

		for(config_t *cfg = lookup_config(&config_tree, "ListenAddress"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
			cfgs++;
			get_config_string(cfg, &address);

			if(!add_listen_address(address, false)) {
				return false;
			}
		}

		if(!cfgs)
			if(!add_listen_address(address, NULL)) {
				return false;
			}
	}

	if(!listen_sockets) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to create any listening socket!");
		return false;
	}

	/* If no Port option was specified, set myport to the port used by the first listening socket. */

	if(!port_specified || atoi(myport.tcp) == 0) {
		listen_socket_t *sock = &listen_socket[0];

		uint16_t tcp = get_bound_port(sock->tcp.fd);
		free(myport.tcp);
		myport.tcp = int_to_str(tcp);

		uint16_t udp = get_bound_port(sock->udp.fd);
		free(myport.udp);
		myport.udp = int_to_str(udp);
	}

	xasprintf(&myself->hostname, "MYSELF port %s", myport.tcp);
	myself->connection->hostname = xstrdup(myself->hostname);

	char *upnp = NULL;
	get_config_string(lookup_config(&config_tree, "UPnP"), &upnp);
	bool upnp_tcp = false;
	bool upnp_udp = false;

	if(upnp) {
		if(!strcasecmp(upnp, "yes")) {
			upnp_tcp = upnp_udp = true;
		} else if(!strcasecmp(upnp, "udponly")) {
			upnp_udp = true;
		}

		free(upnp);
	}

	if(upnp_tcp || upnp_udp) {
#ifdef HAVE_MINIUPNPC
		upnp_init(upnp_tcp, upnp_udp);
#else
		logger(DEBUG_ALWAYS, LOG_WARNING, "UPnP was requested, but tinc isn't built with miniupnpc support!");
#endif
	}

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

	if(get_config_int(lookup_config(&config_tree, "PingInterval"), &pinginterval)) {
		if(pinginterval < 1) {
			pinginterval = 86400;
		}
	} else {
		pinginterval = 60;
	}

	if(!get_config_int(lookup_config(&config_tree, "PingTimeout"), &pingtimeout)) {
		pingtimeout = 5;
	}

	if(pingtimeout < 1 || pingtimeout > pinginterval) {
		pingtimeout = pinginterval;
	}

	if(!get_config_int(lookup_config(&config_tree, "MaxOutputBufferSize"), &maxoutbufsize)) {
		maxoutbufsize = 10 * MTU;
	}

	if(!setup_myself()) {
		return false;
	}

	if(!init_control()) {
		return false;
	}

	if(!device_standby) {
		device_enable();
	}

	/* Run subnet-up scripts for our own subnets */

	subnet_update(myself, NULL, true);

	return true;
}

/*
  close all open network connections
*/
void close_network_connections(void) {
	for(list_node_t *node = connection_list.head, *next; node; node = next) {
		next = node->next;
		connection_t *c = node->data;

		/* Keep control connections open until the end, so they know when we really terminated */
		if(c->status.control) {
			c->socket = -1;
		}

		c->outgoing = NULL;
		terminate_connection(c, false);
	}

	list_empty_list(&outgoing_list);

	if(myself && myself->connection) {
		subnet_update(myself, NULL, false);
		free_connection(myself->connection);
	}

	for(int i = 0; i < listen_sockets; i++) {
		io_del(&listen_socket[i].tcp);
		io_del(&listen_socket[i].udp);
		closesocket(listen_socket[i].tcp.fd);
		closesocket(listen_socket[i].udp.fd);
	}

	exit_requests();
	exit_edges();
	exit_subnets();
	exit_nodes();
	exit_connections();

	if(!device_standby) {
		device_disable();
	}

	free(myport.tcp);
	free(myport.udp);

	if(device_fd >= 0) {
		io_del(&device_io);
	}

	if(devops.close) {
		devops.close();
	}

	exit_control();

	free(scriptextension);
	free(scriptinterpreter);

	return;
}
