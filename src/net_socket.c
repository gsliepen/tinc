/*
    net_socket.c -- Handle various kinds of sockets.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>
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
#include "utils.h"
#include "xalloc.h"

#include <assert.h>

/* Needed on Mac OS/X */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

int addressfamily = AF_UNSPEC;
int maxtimeout = 900;
int seconds_till_retry = 5;

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
		logger(LOG_ERR, "ioctlsocket for %s: %d", c->hostname, sockstrerror(sockerrno));
	}
#endif

#if defined(SOL_TCP) && defined(TCP_NODELAY)
	option = 1;
	setsockopt(c->socket, SOL_TCP, TCP_NODELAY, &option, sizeof(option));
#endif

#if defined(SOL_IP) && defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, SOL_IP, IP_TOS, &option, sizeof(option));
#endif
}

static bool bind_to_interface(int sd) {
	char *iface;

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	struct ifreq ifr;
	int status;
#endif /* defined(SOL_SOCKET) && defined(SO_BINDTODEVICE) */

	if(!get_config_string (lookup_config (config_tree, "BindToInterface"), &iface))
		return true;

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
	ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = 0;

	status = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
	if(status) {
		logger(LOG_ERR, "Can't bind to interface %s: %s", iface,
				strerror(errno));
		return false;
	}
#else /* if !defined(SOL_SOCKET) || !defined(SO_BINDTODEVICE) */
	logger(LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif

	return true;
}

static bool bind_to_address(connection_t *c) {
	char *node;
	struct addrinfo *ai_list;
	struct addrinfo *ai_ptr;
	struct addrinfo ai_hints;
	int status;

	assert(c != NULL);
	assert(c->socket >= 0);

	node = NULL;
	if(!get_config_string(lookup_config(config_tree, "BindToAddress"),
				&node))
		return true;

	assert(node != NULL);

	memset(&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_family = c->address.sa.sa_family;
	/* We're called from `do_outgoing_connection' only. */
	ai_hints.ai_socktype = SOCK_STREAM;
	ai_hints.ai_protocol = IPPROTO_TCP;

	ai_list = NULL;

	status = getaddrinfo(node, /* service = */ NULL,
			&ai_hints, &ai_list);
	if(status) {
		free(node);
		logger(LOG_WARNING, "Error looking up %s port %s: %s",
				node, "any", gai_strerror(status));
		return false;
	}
	assert(ai_list != NULL);

	status = -1;
	for(ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		status = bind(c->socket,
				ai_list->ai_addr, ai_list->ai_addrlen);
		if(!status)
			break;
	}


	if(status) {
		logger(LOG_ERR, "Can't bind to %s/tcp: %s", node, sockstrerror(sockerrno));
	} else ifdebug(CONNECTIONS) {
		logger(LOG_DEBUG, "Successfully bound outgoing "
				"TCP socket to %s", node);
	}

	free(node);
	freeaddrinfo(ai_list);

	return status ? false : true;
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

	/* Optimize TCP settings */

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

#if defined(SOL_IPV6) && defined(IPV6_V6ONLY)
	if(sa->sa.sa_family == AF_INET6)
		setsockopt(nfd, SOL_IPV6, IPV6_V6ONLY, &option, sizeof option);
#endif

	if(get_config_string
	   (lookup_config(config_tree, "BindToInterface"), &iface)) {
#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);

		if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
			closesocket(nfd);
			logger(LOG_ERR, "Can't bind to interface %s: %s", iface,
				   strerror(sockerrno));
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
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

#if defined(SOL_IPV6) && defined(IPV6_V6ONLY)
	if(sa->sa.sa_family == AF_INET6)
		setsockopt(nfd, SOL_IPV6, IPV6_V6ONLY, &option, sizeof option);
#endif

#if defined(SOL_IP) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IP_PMTUDISC_DO;
		setsockopt(nfd, SOL_IP, IP_MTU_DISCOVER, &option, sizeof(option));
	}
#elif defined(IPPROTO_IP) && defined(IP_DONTFRAGMENT)
	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IP, IP_DONTFRAGMENT, &option, sizeof(option));
	}
#endif

#if defined(SOL_IPV6) && defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IPV6_PMTUDISC_DO;
		setsockopt(nfd, SOL_IPV6, IPV6_MTU_DISCOVER, &option, sizeof(option));
	}
#endif

	if (!bind_to_interface(nfd)) {
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

	if(outgoing->timeout > maxtimeout)
		outgoing->timeout = maxtimeout;

	if(outgoing->event)
		event_del(outgoing->event);
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

	configure_tcp(c);

	c->last_ping_time = now;

	send_id(c);
}

void do_outgoing_connection(connection_t *c) {
	char *address, *port;
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

		get_config_string(c->outgoing->cfg, &address);

		if(!get_config_string(lookup_config(c->config_tree, "Port"), &port))
			xasprintf(&port, "655");

		c->outgoing->ai = str2addrinfo(address, port, SOCK_STREAM);
		free(address);
		free(port);

		c->outgoing->aip = c->outgoing->ai;
		c->outgoing->cfg = lookup_config_next(c->config_tree, c->outgoing->cfg);
	}

	if(!c->outgoing->aip) {
		if(c->outgoing->ai)
			freeaddrinfo(c->outgoing->ai);
		c->outgoing->ai = NULL;
		goto begin;
	}

	memcpy(&c->address, c->outgoing->aip->ai_addr, c->outgoing->aip->ai_addrlen);
	c->outgoing->aip = c->outgoing->aip->ai_next;

	if(c->hostname)
		free(c->hostname);

	c->hostname = sockaddr2hostname(&c->address);

	ifdebug(CONNECTIONS) logger(LOG_INFO, "Trying to connect to %s (%s)", c->name,
			   c->hostname);

	c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(c->socket == -1) {
		ifdebug(CONNECTIONS) logger(LOG_ERR, "Creating socket for %s failed: %s", c->hostname, sockstrerror(sockerrno));
		goto begin;
	}

#if defined(SOL_IPV6) && defined(IPV6_V6ONLY)
	int option = 1;
	if(c->address.sa.sa_family == AF_INET6)
		setsockopt(c->socket, SOL_IPV6, IPV6_V6ONLY, &option, sizeof option);
#endif

	bind_to_interface(c->socket);
	bind_to_address(c);

	/* Optimize TCP settings */

	configure_tcp(c);

	/* Connect */

	result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));

	if(result == -1) {
		if(sockinprogress(sockerrno)) {
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
	read_connection_config(c);

	outgoing->cfg = lookup_config(c->config_tree, "Address");

	if(!outgoing->cfg) {
		logger(LOG_ERR, "No address specified for %s", c->name);
		free_connection(c);
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
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	fd = accept(sock, &sa.sa, &len);

	if(fd < 0) {
		logger(LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return false;
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
	send_id(c);

	return true;
}

void free_outgoing(outgoing_t *outgoing) {
	if(outgoing->ai)
		freeaddrinfo(outgoing->ai);

	if(outgoing->name)
		free(outgoing->name);

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
