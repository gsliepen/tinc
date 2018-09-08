/*
    net_socket.c -- Handle various kinds of sockets.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>
                  2009      Florian Forster <octo@verplant.org>

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

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "event.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "proxy.h"
#include "utils.h"
#include "xalloc.h"

/* Needed on Mac OS/X */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

int addressfamily = AF_UNSPEC;
int mintimeout = 0;
int maxtimeout = 900;
int seconds_till_retry = 5;
int udp_rcvbuf = 0;
int udp_sndbuf = 0;

listen_socket_t listen_socket[MAXSOCKETS];
int listen_sockets;
list_t *outgoing_list = NULL;

/* Setup sockets */

static void configure_tcp(connection_t *c) {
	int option;

#ifdef O_NONBLOCK
	int flags = fcntl(c->socket, F_GETFL);

	if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
		logger(LOG_ERR, "fcntl for %s: %s", c->hostname, strerror(errno));
	}

#elif defined(WIN32)
	unsigned long arg = 1;

	if(ioctlsocket(c->socket, FIONBIO, &arg) != 0) {
		logger(LOG_ERR, "ioctlsocket for %s: %s", c->hostname, sockstrerror(sockerrno));
	}

#endif

#if defined(SOL_TCP) && defined(TCP_NODELAY)
	option = 1;
	setsockopt(c->socket, SOL_TCP, TCP_NODELAY, (void *)&option, sizeof(option));
#endif

#if defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, IPPROTO_IP, IP_TOS, (void *)&option, sizeof(option));
#endif

#if defined(IPV6_TCLASS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, IPPROTO_IPV6, IPV6_TCLASS, (void *)&option, sizeof(option));
#endif
}

static bool bind_to_interface(int sd) {
	char *iface;

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	struct ifreq ifr;
	int status;
#endif /* defined(SOL_SOCKET) && defined(SO_BINDTODEVICE) */

	if(!get_config_string(lookup_config(config_tree, "BindToInterface"), &iface)) {
		return true;
	}

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
	ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = 0;
	free(iface);

	status = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));

	if(status) {
		logger(LOG_ERR, "Can't bind to interface %s: %s", ifr.ifr_ifrn.ifrn_name, strerror(errno));
		return false;
	}

#else /* if !defined(SOL_SOCKET) || !defined(SO_BINDTODEVICE) */
	logger(LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif

	return true;
}

int setup_listen_socket(const sockaddr_t *sa) {
	int nfd;
	char *addrstr;
	int option;
	char *iface;

	nfd = socket(sa->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(nfd < 0) {
		ifdebug(STATUS) logger(LOG_ERR, "Creating metasocket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

	/* Optimize TCP settings */

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof(option));

#if defined(IPV6_V6ONLY)

	if(sa->sa.sa_family == AF_INET6) {
		setsockopt(nfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}

#else
#warning IPV6_V6ONLY not defined
#endif

	if(get_config_string(lookup_config(config_tree, "BindToInterface"), &iface)) {
#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
		ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = 0;
		free(iface);

		if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr))) {
			closesocket(nfd);
			logger(LOG_ERR, "Can't bind to interface %s: %s", ifr.ifr_ifrn.ifrn_name, strerror(sockerrno));
			return -1;
		}

#else
		logger(LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(LOG_ERR, "Can't bind to %s/tcp: %s", addrstr, sockstrerror(sockerrno));
		free(addrstr);
		return -1;
	}

	if(listen(nfd, 3)) {
		closesocket(nfd);
		logger(LOG_ERR, "System call `%s' failed: %s", "listen", sockstrerror(sockerrno));
		return -1;
	}

	return nfd;
}

int setup_vpn_in_socket(const sockaddr_t *sa) {
	int nfd;
	char *addrstr;
	int option;

	nfd = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(nfd < 0) {
		logger(LOG_ERR, "Creating UDP socket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(LOG_ERR, "System call `%s' failed: %s", "fcntl",
			       strerror(errno));
			return -1;
		}
	}
#elif defined(WIN32)
	{
		unsigned long arg = 1;

		if(ioctlsocket(nfd, FIONBIO, &arg) != 0) {
			closesocket(nfd);
			logger(LOG_ERR, "Call to `%s' failed: %s", "ioctlsocket", sockstrerror(sockerrno));
			return -1;
		}
	}
#endif

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof(option));
	setsockopt(nfd, SOL_SOCKET, SO_BROADCAST, (void *)&option, sizeof(option));

	if(udp_rcvbuf && setsockopt(nfd, SOL_SOCKET, SO_RCVBUF, (void *)&udp_rcvbuf, sizeof(udp_rcvbuf))) {
		logger(LOG_WARNING, "Can't set UDP SO_RCVBUF to %i: %s", udp_rcvbuf, strerror(errno));
	}

	if(udp_sndbuf && setsockopt(nfd, SOL_SOCKET, SO_SNDBUF, (void *)&udp_sndbuf, sizeof(udp_sndbuf))) {
		logger(LOG_WARNING, "Can't set UDP SO_SNDBUF to %i: %s", udp_sndbuf, strerror(errno));
	}

#if defined(IPV6_V6ONLY)

	if(sa->sa.sa_family == AF_INET6) {
		setsockopt(nfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}

#endif

#if defined(IP_DONTFRAG) && !defined(IP_DONTFRAGMENT)
#define IP_DONTFRAGMENT IP_DONTFRAG
#endif

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IP_PMTUDISC_DO;
		setsockopt(nfd, IPPROTO_IP, IP_MTU_DISCOVER, (void *)&option, sizeof(option));
	}

#elif defined(IP_DONTFRAGMENT)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IP, IP_DONTFRAGMENT, (void *)&option, sizeof(option));
	}

#endif

#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IPV6_PMTUDISC_DO;
		setsockopt(nfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (void *)&option, sizeof(option));
	}

#elif defined(IPV6_DONTFRAG)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IPV6, IPV6_DONTFRAG, (void *)&option, sizeof(option));
	}

#endif

	if(!bind_to_interface(nfd)) {
		closesocket(nfd);
		return -1;
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(LOG_ERR, "Can't bind to %s/udp: %s", addrstr, sockstrerror(sockerrno));
		free(addrstr);
		return -1;
	}

	return nfd;
} /* int setup_vpn_in_socket */

void retry_outgoing(outgoing_t *outgoing) {
	outgoing->timeout += 5;

	if(outgoing->timeout < mintimeout) {
		outgoing->timeout = mintimeout;
	}

	if(outgoing->timeout > maxtimeout) {
		outgoing->timeout = maxtimeout;
	}

	if(outgoing->event) {
		event_del(outgoing->event);
	}

	outgoing->event = new_event();
	outgoing->event->handler = (event_handler_t) setup_outgoing_connection;
	outgoing->event->time = now + outgoing->timeout;
	outgoing->event->data = outgoing;
	event_add(outgoing->event);

	ifdebug(CONNECTIONS) logger(LOG_NOTICE,
	                            "Trying to re-establish outgoing connection in %d seconds",
	                            outgoing->timeout);
}

void finish_connecting(connection_t *c) {
	ifdebug(CONNECTIONS) logger(LOG_INFO, "Connected to %s (%s)", c->name, c->hostname);

	c->last_ping_time = now;

	send_id(c);
}

static void do_outgoing_pipe(connection_t *c, char *command) {
#ifndef HAVE_MINGW
	int fd[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		logger(LOG_ERR, "Could not create socketpair: %s\n", strerror(errno));
		return;
	}

	if(fork()) {
		c->socket = fd[0];
		close(fd[1]);
		ifdebug(CONNECTIONS) logger(LOG_DEBUG, "Using proxy %s", command);
		return;
	}

	close(0);
	close(1);
	close(fd[0]);
	dup2(fd[1], 0);
	dup2(fd[1], 1);
	close(fd[1]);

	// Other filedescriptors should be closed automatically by CLOEXEC

	char *host = NULL;
	char *port = NULL;

	sockaddr2str(&c->address, &host, &port);
	setenv("REMOTEADDRESS", host, true);
	setenv("REMOTEPORT", port, true);
	setenv("NODE", c->name, true);
	setenv("NAME", myself->name, true);

	if(netname) {
		setenv("NETNAME", netname, true);
	}

	int result = system(command);

	if(result < 0) {
		logger(LOG_ERR, "Could not execute %s: %s\n", command, strerror(errno));
	} else if(result) {
		logger(LOG_ERR, "%s exited with non-zero status %d", command, result);
	}

	exit(result);
#else
	logger(LOG_ERR, "Proxy type exec not supported on this platform!");
	return;
#endif
}

static bool is_valid_host_port(const char *host, const char *port) {
	for(const char *p = host; *p; p++)
		if(!isalnum(*p) && *p != '-' && *p != '.') {
			return false;
		}

	for(const char *p = port; *p; p++)
		if(!isalnum(*p)) {
			return false;
		}

	return true;
}

void do_outgoing_connection(connection_t *c) {
	struct addrinfo *proxyai = NULL;
	int result;

	if(!c->outgoing) {
		logger(LOG_ERR, "do_outgoing_connection() for %s called without c->outgoing", c->name);
		abort();
	}

begin:

	if(!c->outgoing->ai) {
		if(!c->outgoing->cfg) {
			ifdebug(CONNECTIONS) logger(LOG_ERR, "Could not set up a meta connection to %s",
			                            c->name);
			c->status.remove = true;
			retry_outgoing(c->outgoing);
			c->outgoing = NULL;
			return;
		}

		char *address, *port, *space;

		get_config_string(c->outgoing->cfg, &address);

		space = strchr(address, ' ');

		if(space) {
			port = xstrdup(space + 1);
			*space = 0;
		} else {
			if(!get_config_string(lookup_config(c->config_tree, "Port"), &port)) {
				port = xstrdup("655");
			}
		}

		c->outgoing->ai = str2addrinfo(address, port, SOCK_STREAM);

		// If we cannot resolve the address, maybe we are using a proxy that can?
		if(!c->outgoing->ai && proxytype != PROXY_NONE && is_valid_host_port(address, port)) {
			memset(&c->address, 0, sizeof(c->address));
			c->address.sa.sa_family = AF_UNKNOWN;
			c->address.unknown.address = address;
			c->address.unknown.port = port;
		} else {
			free(address);
			free(port);
		}

		c->outgoing->aip = c->outgoing->ai;
		c->outgoing->cfg = lookup_config_next(c->config_tree, c->outgoing->cfg);

		if(!c->outgoing->ai && proxytype != PROXY_NONE) {
			goto connect;
		}
	}

	if(!c->outgoing->aip) {
		if(c->outgoing->ai) {
			freeaddrinfo(c->outgoing->ai);
		}

		c->outgoing->ai = NULL;
		goto begin;
	}

	memcpy(&c->address, c->outgoing->aip->ai_addr, c->outgoing->aip->ai_addrlen);
	c->outgoing->aip = c->outgoing->aip->ai_next;

connect:

	if(c->hostname) {
		free(c->hostname);
	}

	c->hostname = sockaddr2hostname(&c->address);

	ifdebug(CONNECTIONS) logger(LOG_INFO, "Trying to connect to %s (%s)", c->name,
	                            c->hostname);

	if(!proxytype) {
		c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	} else if(proxytype == PROXY_EXEC) {
		c->status.proxy_passed = true;
		do_outgoing_pipe(c, proxyhost);
	} else {
		proxyai = str2addrinfo(proxyhost, proxyport, SOCK_STREAM);

		if(!proxyai) {
			goto begin;
		}

		ifdebug(CONNECTIONS) logger(LOG_INFO, "Using proxy at %s port %s", proxyhost, proxyport);
		c->socket = socket(proxyai->ai_family, SOCK_STREAM, IPPROTO_TCP);
	}

	if(c->socket == -1) {
		ifdebug(CONNECTIONS) logger(LOG_ERR, "Creating socket for %s failed: %s", c->hostname, sockstrerror(sockerrno));
		goto begin;
	}

	if(proxytype != PROXY_EXEC) {
		configure_tcp(c);
	}

#ifdef FD_CLOEXEC
	fcntl(c->socket, F_SETFD, FD_CLOEXEC);
#endif

	if(proxytype != PROXY_EXEC) {
#if defined(IPV6_V6ONLY)
		int option = 1;

		if(c->address.sa.sa_family == AF_INET6) {
			setsockopt(c->socket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
		}

#endif

		bind_to_interface(c->socket);

		int b = -1;

		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == c->address.sa.sa_family) {
				if(b == -1) {
					b = i;
				} else  {
					b = -1;
					break;
				}
			}
		}

		if(b != -1) {
			sockaddr_t sa = listen_socket[b].sa;

			if(sa.sa.sa_family == AF_INET) {
				sa.in.sin_port = 0;
			} else if(sa.sa.sa_family == AF_INET6) {
				sa.in6.sin6_port = 0;
			}

			if(bind(c->socket, &sa.sa, SALEN(sa.sa))) {
				char *addrstr = sockaddr2hostname(&sa);
				logger(LOG_ERR, "Can't bind to %s/tcp: %s", addrstr, sockstrerror(sockerrno));
				free(addrstr);
			}
		}
	}

	/* Connect */

	if(!proxytype) {
		result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));
	} else if(proxytype == PROXY_EXEC) {
		result = 0;
	} else {
		result = connect(c->socket, proxyai->ai_addr, proxyai->ai_addrlen);
		freeaddrinfo(proxyai);
	}

	now = time(NULL);

	if(result == -1) {
		if(sockinprogress(sockerrno)) {
			c->last_ping_time = now;
			c->status.connecting = true;
			return;
		}

		closesocket(c->socket);

		ifdebug(CONNECTIONS) logger(LOG_ERR, "%s: %s", c->hostname, sockstrerror(sockerrno));

		goto begin;
	}

	finish_connecting(c);

	return;
}

void setup_outgoing_connection(outgoing_t *outgoing) {
	connection_t *c;
	node_t *n;

	outgoing->event = NULL;

	n = lookup_node(outgoing->name);

	if(n)
		if(n->connection) {
			ifdebug(CONNECTIONS) logger(LOG_INFO, "Already connected to %s", outgoing->name);

			n->connection->outgoing = outgoing;
			return;
		}

	c = new_connection();
	c->name = xstrdup(outgoing->name);
	c->outcipher = myself->connection->outcipher;
	c->outdigest = myself->connection->outdigest;
	c->outmaclength = myself->connection->outmaclength;
	c->outcompression = myself->connection->outcompression;

	init_configuration(&c->config_tree);

	if(!read_connection_config(c)) {
		free_connection(c);
		outgoing->timeout = maxtimeout;
		retry_outgoing(outgoing);
		return;
	}

	outgoing->cfg = lookup_config(c->config_tree, "Address");

	if(!outgoing->cfg) {
		logger(LOG_ERR, "No address specified for %s", c->name);
		free_connection(c);
		outgoing->timeout = maxtimeout;
		retry_outgoing(outgoing);
		return;
	}

	c->outgoing = outgoing;
	c->last_ping_time = now;

	connection_add(c);

	do_outgoing_connection(c);
}

/*
  accept a new tcp connect and create a
  new connection
*/
bool handle_new_meta_connection(int sock) {
	static const int max_accept_burst = 10;
	static int last_accept_burst;
	static int last_accept_time;
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	fd = accept(sock, &sa.sa, &len);

	if(fd < 0) {
		logger(LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return false;
	}

	if(last_accept_time == now) {
		last_accept_burst++;

		if(last_accept_burst >= max_accept_burst) {
			if(last_accept_burst == max_accept_burst) {
				ifdebug(CONNECTIONS) logger(LOG_WARNING, "Throttling incoming connections");
			}

			tarpit(fd);
			return false;
		}
	} else {
		last_accept_burst = 0;
		last_accept_time = now;
	}

	sockaddrunmap(&sa);

	c = new_connection();
	c->name = xstrdup("<unknown>");
	c->outcipher = myself->connection->outcipher;
	c->outdigest = myself->connection->outdigest;
	c->outmaclength = myself->connection->outmaclength;
	c->outcompression = myself->connection->outcompression;

	c->address = sa;
	c->hostname = sockaddr2hostname(&sa);
	c->socket = fd;
	c->last_ping_time = now;

	ifdebug(CONNECTIONS) logger(LOG_NOTICE, "Connection from %s", c->hostname);

	configure_tcp(c);

	connection_add(c);

	c->allow_request = ID;

	return true;
}

static void free_outgoing(outgoing_t *outgoing) {
	if(outgoing->ai) {
		freeaddrinfo(outgoing->ai);
	}

	if(outgoing->name) {
		free(outgoing->name);
	}

	free(outgoing);
}

void try_outgoing_connections(void) {
	static config_t *cfg = NULL;
	char *name;
	outgoing_t *outgoing;

	outgoing_list = list_alloc((list_action_t)free_outgoing);

	for(cfg = lookup_config(config_tree, "ConnectTo"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		get_config_string(cfg, &name);

		if(!check_id(name)) {
			logger(LOG_ERR,
			       "Invalid name for outgoing connection in %s line %d",
			       cfg->file, cfg->line);
			free(name);
			continue;
		}

		outgoing = xmalloc_and_zero(sizeof(*outgoing));
		outgoing->name = name;
		list_insert_tail(outgoing_list, outgoing);
		setup_outgoing_connection(outgoing);
	}
}
