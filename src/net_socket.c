/*
    net_socket.c -- Handle various kinds of sockets.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2008 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
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

#ifdef WSAEINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif

/* Needed on Mac OS/X */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

int addressfamily = AF_UNSPEC;
int maxtimeout = 900;
int seconds_till_retry = 5;

listen_socket_t listen_socket[MAXSOCKETS];
int listen_sockets;

/* Setup sockets */

static void configure_tcp(connection_t *c)
{
	int option;

#ifdef O_NONBLOCK
	int flags = fcntl(c->socket, F_GETFL);

	if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
		logger(LOG_ERR, _("fcntl for %s: %s"), c->hostname, strerror(errno));
	}
#elif defined(WIN32)
	unsigned long arg = 1;

	if(ioctlsocket(c->socket, FIONBIO, &arg) != 0) {
		logger(LOG_ERR, _("ioctlsocket for %s: WSA error %d"), c->hostname, WSAGetLastError());
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

int setup_listen_socket(const sockaddr_t *sa)
{
	int nfd;
	char *addrstr;
	int option;
	char *iface;

	cp();

	nfd = socket(sa->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(nfd < 0) {
		ifdebug(STATUS) logger(LOG_ERR, _("Creating metasocket failed: %s"), strerror(errno));
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
			logger(LOG_ERR, _("Can't bind to interface %s: %s"), iface,
				   strerror(errno));
			return -1;
		}
#else
		logger(LOG_WARNING, _("BindToInterface not supported on this platform"));
#endif
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(LOG_ERR, _("Can't bind to %s/tcp: %s"), addrstr,
			   strerror(errno));
		free(addrstr);
		return -1;
	}

	if(listen(nfd, 3)) {
		closesocket(nfd);
		logger(LOG_ERR, _("System call `%s' failed: %s"), "listen",
			   strerror(errno));
		return -1;
	}

	return nfd;
}

int setup_vpn_in_socket(const sockaddr_t *sa)
{
	int nfd;
	char *addrstr;
	int option;

	cp();

	nfd = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(nfd < 0) {
		logger(LOG_ERR, _("Creating UDP socket failed: %s"), strerror(errno));
		return -1;
	}

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl",
				   strerror(errno));
			return -1;
		}
	}
#elif defined(WIN32)
	{
		unsigned long arg = 1;
		if(ioctlsocket(nfd, FIONBIO, &arg) != 0) {
			closesocket(nfd);
			logger(LOG_ERR, _("Call to `%s' failed: WSA error %d"), "ioctlsocket",
				WSAGetLastError());
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
	{
		bool choice;

		if(!get_config_bool(lookup_config(myself->connection->config_tree, "PMTUDiscovery"), &choice) || choice) {
			option = IP_PMTUDISC_DO;
			setsockopt(nfd, SOL_IP, IP_MTU_DISCOVER, &option, sizeof(option));
		}
	}
#endif

#if defined(SOL_IPV6) && defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
	{
		bool choice;

		if(!get_config_bool(lookup_config(myself->connection->config_tree, "PMTUDiscovery"), &choice) || choice) {
			option = IPV6_PMTUDISC_DO;
			setsockopt(nfd, SOL_IPV6, IPV6_MTU_DISCOVER, &option, sizeof(option));
		}
	}
#endif

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	{
		char *iface;
		struct ifreq ifr;

		if(get_config_string(lookup_config(config_tree, "BindToInterface"), &iface)) {
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);

			if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
				closesocket(nfd);
				logger(LOG_ERR, _("Can't bind to interface %s: %s"), iface,
					   strerror(errno));
				return -1;
			}
		}
	}
#endif

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(LOG_ERR, _("Can't bind to %s/udp: %s"), addrstr,
			   strerror(errno));
		free(addrstr);
		return -1;
	}

	return nfd;
}

void retry_outgoing(outgoing_t *outgoing)
{
	event_t *event;

	cp();

	outgoing->timeout += 5;

	if(outgoing->timeout > maxtimeout)
		outgoing->timeout = maxtimeout;

	event = new_event();
	event->handler = (event_handler_t) setup_outgoing_connection;
	event->time = now + outgoing->timeout;
	event->data = outgoing;
	event_add(event);

	ifdebug(CONNECTIONS) logger(LOG_NOTICE,
			   _("Trying to re-establish outgoing connection in %d seconds"),
			   outgoing->timeout);
}

void finish_connecting(connection_t *c)
{
	cp();

	ifdebug(CONNECTIONS) logger(LOG_INFO, _("Connected to %s (%s)"), c->name, c->hostname);

	configure_tcp(c);

	c->last_ping_time = now;

	send_id(c);
}

void do_outgoing_connection(connection_t *c)
{
	char *address, *port;
	int result;

	cp();

begin:
	if(!c->outgoing->ai) {
		if(!c->outgoing->cfg) {
			ifdebug(CONNECTIONS) logger(LOG_ERR, _("Could not set up a meta connection to %s"),
					   c->name);
			c->status.remove = true;
			retry_outgoing(c->outgoing);
			return;
		}

		get_config_string(c->outgoing->cfg, &address);

		if(!get_config_string(lookup_config(c->config_tree, "Port"), &port))
			asprintf(&port, "655");

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

	ifdebug(CONNECTIONS) logger(LOG_INFO, _("Trying to connect to %s (%s)"), c->name,
			   c->hostname);

	c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(c->socket == -1) {
		ifdebug(CONNECTIONS) logger(LOG_ERR, _("Creating socket for %s failed: %s"), c->hostname,
				   strerror(errno));

		goto begin;
	}

#if defined(SOL_IPV6) && defined(IPV6_V6ONLY)
	int option = 1;
	if(c->address.sa.sa_family == AF_INET6)
		setsockopt(c->socket, SOL_IPV6, IPV6_V6ONLY, &option, sizeof option);
#endif

	/* Optimize TCP settings */

	configure_tcp(c);

	/* Connect */

	result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));

	if(result == -1) {
		if(errno == EINPROGRESS
#if defined(WIN32) && !defined(O_NONBLOCK)
		   || WSAGetLastError() == WSAEWOULDBLOCK
#endif
		) {
			c->status.connecting = true;
			return;
		}

		closesocket(c->socket);

		ifdebug(CONNECTIONS) logger(LOG_ERR, _("%s: %s"), c->hostname, strerror(errno));

		goto begin;
	}

	finish_connecting(c);

	return;
}

void setup_outgoing_connection(outgoing_t *outgoing)
{
	connection_t *c;
	node_t *n;

	cp();

	n = lookup_node(outgoing->name);

	if(n)
		if(n->connection) {
			ifdebug(CONNECTIONS) logger(LOG_INFO, _("Already connected to %s"), outgoing->name);

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
		logger(LOG_ERR, _("No address specified for %s"), c->name);
		free_connection(c);
		free(outgoing->name);
		free(outgoing);
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
bool handle_new_meta_connection(int sock)
{
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	cp();

	fd = accept(sock, &sa.sa, &len);

	if(fd < 0) {
		logger(LOG_ERR, _("Accepting a new connection failed: %s"),
			   strerror(errno));
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

	ifdebug(CONNECTIONS) logger(LOG_NOTICE, _("Connection from %s"), c->hostname);

	configure_tcp(c);

	connection_add(c);

	c->allow_request = ID;
	send_id(c);

	return true;
}

void try_outgoing_connections(void)
{
	static config_t *cfg = NULL;
	char *name;
	outgoing_t *outgoing;

	cp();

	for(cfg = lookup_config(config_tree, "ConnectTo"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		get_config_string(cfg, &name);

		if(!check_id(name)) {
			logger(LOG_ERR,
				   _("Invalid name for outgoing connection in %s line %d"),
				   cfg->file, cfg->line);
			free(name);
			continue;
		}

		outgoing = xmalloc_and_zero(sizeof(*outgoing));
		outgoing->name = name;
		setup_outgoing_connection(outgoing);
	}
}
